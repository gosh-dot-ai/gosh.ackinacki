// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Live shellnet E2E for the airegistry (SPC token) marketplace.
//!
//! Env-gated (`GOSH_AIREGISTRY_E2E=1`). Shellnet is a testnet; the Giver mints
//! free SHELL, so this spends nothing real. One test walks the whole
//! creator + consumer lifecycle on the live chain, then budget delegation, then
//! the negative branches — verified by exact getter state + ECC[2] balances:
//!
//!   CREATOR   SuperRoot → RootModel → ManifestMetadata (the REAL vendored SPC
//!             package stored IN FULL on-chain — indexed chunks via
//!             setApiSchemaChunk, then read back byte-for-byte) → TokenContract,
//!             each self-registering with its parent; every address cross-checked
//!             against the parent's derivation getter.
//!   CONSUMER  a multisig wallet funded with free SHELL drives the lot with
//!             REAL ECC[2] payments: buyTokens → consumeSession (seller bills,
//!             first batch then one session each) → auto-release → withdrawShell
//!             (asserts the recipient was actually credited).
//!   DELEGATION a 2-of-3 treasury governs a 1-sig operational budget: a single
//!             custodian's top-up only QUEUES (bypass blocked), a second
//!             confirms it, then the operational wallet spends with one signature.
//!   NEGATIVES (not happy-path-only): under-delivery → buyer cancels remainder
//!             (refund + unlock, seller keeps billed); over-withdraw
//!             (withdrawShell > sellerOwed) rejected, then exact withdraw after
//!             cancel succeeds; over-budget/sold-out buy bounces the SHELL back;
//!             post-first-batch multi-session consume blocked; fee/burn
//!             (paid-fee held, fee burned);
//!             lock-conflict (2nd buyer rejected, refunded); governance-bypass
//!             (1 sig can't move the treasury); code-hash lock (wrong
//!             rootModelCode never yields a working SuperRoot).
//!
//! Run: `GOSH_AIREGISTRY_E2E=1 cargo test --test e2e_airegistry -- --nocapture`
//! (single test ⇒ no intra-suite races on the shared Giver account).

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use gosh_ackinacki::airegistry::abi::Contract;
use gosh_ackinacki::airegistry::calls::{
    encode_external_call, encode_internal_payload, wallet_forward,
};
use gosh_ackinacki::airegistry::deploy::{build_deploy, local_context, DeployMessage};
use gosh_ackinacki::airegistry::events::{decode_event_body_b64, AiRegistryEvent};
use gosh_ackinacki::airegistry::getter::{AccountOrigin, AccountReader};
use gosh_ackinacki::airegistry::run::{no_args, GetterRunner};
use gosh_ackinacki::config::AiRegistryConfig;
use gosh_ackinacki::wallet::contracts::{MULTISIG_ABI_JSON, MULTISIG_TVC};
use gosh_ackinacki::wallet::giver::GiverClient;
use gosh_ackinacki::wallet::query::send_message;

use std::sync::Arc;
use tvm_client::ClientContext;

const SHELLNET: &str = "https://shellnet.ackinacki.org";
const GAS_VMSHELL: u128 = 1_000_000_000; // 1 vmshell forwarded per call (mirrors BuyerWallet)
const DEPLOY_FUND: u128 = 200_000_000_000; // native vmshell for an uninit deploy address

/// A real SPC swarm package (gosh.swarm.package.v1, 144 records, ~127 KB). It is
/// stored IN FULL on-chain in ManifestMetadata (chunked, since it exceeds one
/// message); the test pins the canonical hash and round-trips the whole package
/// from chain byte-for-byte — proving the blockchain is the only source of truth.
const SPC_PACKAGE: &str = include_str!("fixtures/swarm-package.avm-implementation.v1.jsonl");

/// Canonical sha256 of the vendored SPC package — pinned so a truncated or
/// mutated fixture fails the test immediately (refresh via `make sync-spc-fixture`).
const SPC_PACKAGE_SHA256: &str = "da30f4dab60dc59788d753457c4575b2d1e0a18fb3696fe550934d623ef38481";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// On-demand liveness probe: reports whether shellnet is currently producing
/// blocks. Unlike the full E2E this only READS, so it works even when the chain
/// is halted — that's exactly the case it exists to diagnose (a halted chain
/// keeps serving reads while rejecting every write with QUEUE_OVERFLOW).
///
/// Run: `cargo test --test e2e_airegistry chain_liveness_probe -- --ignored --nocapture`
#[tokio::test]
#[ignore]
async fn chain_liveness_probe() {
    let reader = AccountReader::new(reqwest::Client::new(), SHELLNET);
    let l = reader.chain_liveness(60).await.expect("liveness probe");
    eprintln!(
        "shellnet liveness: newest block #{} is {}s old (threshold {}s) → {}",
        l.latest_seq_no,
        l.latest_block_age_secs,
        l.stale_after_secs,
        if l.is_live() { "LIVE" } else { "HALTED" }
    );
}

/// Split `s` into `<= max_bytes` pieces on UTF-8 char boundaries (so the
/// on-chain concatenation reproduces `s` byte-for-byte).
fn chunk_str(s: &str, max_bytes: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + max_bytes).min(s.len());
        while end > start && !s.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&s[start..end]);
        start = end;
    }
    if out.is_empty() {
        out.push("");
    }
    out
}

struct Keys {
    public: String,
    secret: String,
}

fn gen_keys() -> Keys {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    Keys {
        public: hex::encode(sk.verifying_key().as_bytes()),
        secret: hex::encode(sk.to_bytes()),
    }
}

impl Keys {
    /// A canonical keypair from a fixed secret (deterministic address). Used for
    /// the structural graph (SuperRoot / RootModel owner / manifest / treasury /
    /// operational / consumer wallet) so re-runs reuse the deploy-if-missing
    /// contracts. Token lots stay fresh per run (their escrow state machine must
    /// be pristine for the assertions).
    fn from_secret(secret_hex: &str) -> Keys {
        let bytes: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
        let sk = SigningKey::from_bytes(&bytes);
        Keys {
            public: hex::encode(sk.verifying_key().as_bytes()),
            secret: secret_hex.to_string(),
        }
    }
}

// Canonical fixed keys (§12): deterministic ⇒ canonical addresses, deploy-if-missing.
const SR_SECRET: &str = "1fdb92d928463d40dcf5fe58dcd228ba9663858fccc203930771ef9670768dbf";
const SELLER_SECRET: &str = "ee24841e558adb0594a1bb215439c8737d5ef01f637fafb097a7869a81ed708c";
const MANIFEST_SECRET: &str = "1de37606463f114ac3c0083b2f59753684344e3701291daf0810bbd2957a94ed";
const CONSUMER_SECRET: &str = "a9760fd4891336dd1ebba789ee8380422c1bc2dcdd830311acf53cb9c88ec3ed";
const T1_SECRET: &str = "5b89ac20999526cd9577529852a030aa2184fb3789d49448be6eec0f8a9374d5";
const T2_SECRET: &str = "e671f70264d5cb68ee651120eaa6356a7569e5d25cb5fdb02992eab2aeea8bf8";
const T3_SECRET: &str = "195910f3a63dbcbf4784b2ae44edbc86dfb370c9398ecc71d032bf2b2d02032d";
const O1_SECRET: &str = "c18a788cd9490103383e392636856b6dd4254f96420b61d7df8becc1c9746cb1";
const O2_SECRET: &str = "9415edc49daeef0aebce5fbb583bafd07d89a5db6cd53b9fc455dcd465208528";
const O3_SECRET: &str = "691e1b8b420a9a70298364d1e862b4b9cccba9b02ac6070517e0851b93b566f8";

// ----- account-status polling -------------------------------------------

async fn wait_status(
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    addr: &str,
    target: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let snap = reader
            .fetch(cfg, addr, &AccountOrigin::SelfOriginating)
            .await?;
        let cur = snap
            .as_ref()
            .map(|s| s.acc_type_name.as_str())
            .unwrap_or("NotFound");
        if cur == target {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timeout waiting for {addr} to become {target} (now {cur})");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn deploy_and_wait(
    http: &reqwest::Client,
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    giver: &GiverClient,
    msg: &DeployMessage,
) -> Result<()> {
    if reader
        .is_active(cfg, &msg.address, &AccountOrigin::SelfOriginating)
        .await?
    {
        eprintln!("  {} already Active, reusing", msg.address);
        return Ok(());
    }
    giver.fund_deploy_address(&msg.address, DEPLOY_FUND).await?;
    wait_status(reader, cfg, &msg.address, "Uninit").await?;
    let resp = send_message(http, SHELLNET, &msg.message_boc_b64).await?;
    let exit = resp.pointer("/result/exit_code").and_then(|v| v.as_i64());
    if exit.is_some() && exit != Some(0) {
        bail!("deploy {} non-zero exit: {resp}", msg.address);
    }
    wait_status(reader, cfg, &msg.address, "Active").await?;
    Ok(())
}

// ----- getter helpers ----------------------------------------------------

/// Run a getter against the live account's fetched BOC.
async fn getter(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    abi_json: &str,
    addr: &str,
    method: &str,
    args: Value,
) -> Result<Value> {
    let snap = reader
        .fetch(cfg, addr, &AccountOrigin::SelfOriginating)
        .await?
        .ok_or_else(|| anyhow!("{addr} not found for getter {method}"))?;
    runner
        .run_getter(abi_json, addr, snap.boc.as_ref().unwrap(), method, args)
        .await
}

/// Aggregated TokenContract state (the escrow counters + lock + balance).
#[derive(Debug, Clone)]
struct Tc {
    available: u128,
    sold: u128,
    reserved: u128,
    consume_calls: u128,
    seller_owed: u128,
    shell: u128,
    buyer: String,
}

fn u128f(d: &Value, k: &str) -> u128 {
    d.get(k)
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .parse()
        .unwrap_or(0)
}

async fn token_state(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    tc: &str,
) -> Result<Tc> {
    // Narrow getters, not the full `getDetails` tuple: locally executing
    // `getDetails` aborts ("no output message") — the same limitation the
    // upstream airegistry test works around by reading the counters piecemeal.
    let abi = Contract::TokenContract.abi_json();
    let cnt = getter(reader, runner, cfg, abi, tc, "getCounters", no_args()).await?;
    let cb = getter(reader, runner, cfg, abi, tc, "getCurrentBuyer", no_args()).await?;
    let sb = getter(reader, runner, cfg, abi, tc, "getShellBalance", no_args()).await?;
    Ok(Tc {
        available: u128f(&cnt, "availableTokens"),
        sold: u128f(&cnt, "soldTokens"),
        reserved: u128f(&cnt, "reservedTokens"),
        consume_calls: u128f(&cnt, "consumeCalls"),
        seller_owed: u128f(&cnt, "sellerOwed"),
        shell: u128f(&sb, "value0"),
        buyer: cb
            .get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Poll TokenContract state until `pred` holds, or fail with the last snapshot.
async fn wait_tc<F: Fn(&Tc) -> bool>(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    tc: &str,
    pred: F,
    ctx: &str,
) -> Result<Tc> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = token_state(reader, runner, cfg, tc).await?;
    loop {
        if pred(&last) {
            return Ok(last);
        }
        if Instant::now() > deadline {
            bail!("timeout waiting for {ctx}; last state: {last:?}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        last = token_state(reader, runner, cfg, tc).await?;
    }
}

fn is_zero_addr(a: &str) -> bool {
    a.is_empty() || a.trim_start_matches("0:").chars().all(|c| c == '0')
}

/// Catch an airegistry event (§2.5): poll the contract's ext-out (msg_type 2)
/// messages via GraphQL, decode each body against `abi`, return the first that
/// matches `pred`. This is the spec's event-driven confirmation, complementing
/// the getter-state assertions.
async fn catch_event<F: Fn(&AiRegistryEvent) -> bool>(
    http: &reqwest::Client,
    abi: &tvm_abi::Contract,
    addr: &str,
    pred: F,
    label: &str,
) -> Result<AiRegistryEvent> {
    let bare = addr.trim_start_matches("0:");
    let q = json!({ "query": format!(
        "{{ blockchain {{ account(account_id:\"{bare}\", dapp_id:\"{bare}\") {{ messages(last:50){{ edges {{ node {{ msg_type body }} }} }} }} }} }}"
    )});
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let resp: serde_json::Value = http
            .post(format!("{SHELLNET}/graphql"))
            .json(&q)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let edges = resp
            .pointer("/data/blockchain/account/messages/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for e in edges {
            if e.pointer("/node/msg_type").and_then(|v| v.as_i64()) == Some(2) {
                if let Some(body) = e.pointer("/node/body").and_then(|v| v.as_str()) {
                    if let Ok(ev) = decode_event_body_b64(abi, body) {
                        if pred(&ev) {
                            return Ok(ev);
                        }
                    }
                }
            }
        }
        if Instant::now() > deadline {
            bail!("timeout catching event: {label}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Read an account's ECC[`ecc_id`] balance from GraphQL `info.balance_other`
/// (hex-encoded value). Returns 0 when the account or that currency is absent —
/// used to assert SHELL actually moved (recipient credited / wallet refunded),
/// not just that a contract counter changed.
async fn ecc_balance(http: &reqwest::Client, addr: &str, ecc_id: u64) -> Result<u128> {
    let bare = addr.trim_start_matches("0:");
    let q = json!({
        "query": format!(
            "{{ blockchain {{ account(account_id:\"{bare}\", dapp_id:\"{bare}\") \
             {{ info {{ balance_other {{ currency value }} }} }} }} }}"
        )
    });
    let resp = http
        .post(format!("{SHELLNET}/graphql"))
        .json(&q)
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    let arr = resp
        .pointer("/data/blockchain/account/info/balance_other")
        .and_then(|v| v.as_array());
    let mut out = 0u128;
    if let Some(arr) = arr {
        for e in arr {
            if e.get("currency").and_then(|v| v.as_f64()).map(|f| f as u64) == Some(ecc_id) {
                let raw = e.get("value").and_then(|v| v.as_str()).unwrap_or("0");
                out = match raw.strip_prefix("0x") {
                    Some(h) => u128::from_str_radix(h, 16).unwrap_or(0),
                    None => raw.parse().unwrap_or(0),
                };
            }
        }
    }
    Ok(out)
}

// ----- creator-side deploys ---------------------------------------------

async fn deploy_super_root(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    giver: &GiverClient,
    sr: &Keys,
) -> Result<String> {
    let rm_code = Contract::RootModel.code_boc_b64()?;
    let mf_code = Contract::ManifestMetadata.code_boc_b64()?;
    let msg = build_deploy(
        ctx,
        Contract::SuperRoot.abi_json(),
        Contract::SuperRoot.tvc(),
        json!({}),
        json!({ "pubkey": format!("0x{}", sr.public), "rootModelCode": rm_code, "manifestCode": mf_code }),
        &sr.public,
        &sr.secret,
    )
    .await?;
    eprintln!("SuperRoot → {}", msg.address);
    deploy_and_wait(http, reader, cfg, giver, &msg).await?;
    Ok(msg.address)
}

async fn deploy_root_model(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    giver: &GiverClient,
    owner: &Keys,
    sr_addr: &str,
) -> Result<String> {
    let tc_code = Contract::TokenContract.code_boc_b64()?;
    let msg = build_deploy(
        ctx,
        Contract::RootModel.abi_json(),
        Contract::RootModel.tvc(),
        json!({ "_ownerPubkey": format!("0x{}", owner.public), "_superRootAddress": sr_addr }),
        json!({ "tokenContractCode": tc_code }),
        &owner.public,
        &owner.secret,
    )
    .await?;
    eprintln!("RootModel → {}", msg.address);
    deploy_and_wait(http, reader, cfg, giver, &msg).await?;
    Ok(msg.address)
}

#[allow(clippy::too_many_arguments)]
async fn deploy_token_contract(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    giver: &GiverClient,
    seller: &Keys,
    rm_addr: &str,
    nonce: u64,
    total: u128,
    burn_fee_bps: u16,
) -> Result<String> {
    let msg = build_deploy(
        ctx,
        Contract::TokenContract.abi_json(),
        Contract::TokenContract.tvc(),
        json!({
            "_sellerPubkey": format!("0x{}", seller.public),
            "_rootModelAddress": rm_addr,
            "_nonce": nonce.to_string(),
        }),
        json!({
            "modelName": "GPT-X",
            "endpoint": "https://api.example.com/v1",
            "totalTokensForSale": total.to_string(),
            "tickSize": "1",
            "burnFeeBps": burn_fee_bps,
            "maxReservedSessions": 3,
        }),
        &seller.public,
        &seller.secret,
    )
    .await?;
    eprintln!(
        "TokenContract(nonce={nonce}, burnFeeBps={burn_fee_bps}) → {}",
        msg.address
    );
    deploy_and_wait(http, reader, cfg, giver, &msg).await?;
    Ok(msg.address)
}

/// Deploy a 1-of-1 operational multisig wallet, fund it with native vmshell
/// (gas) and `shell_ecc` units of ECC[2] SHELL (spend budget).
/// Deploy an N-custodian SwarmMultisig wallet (`req_confirms`-of-N). `owners[0]`
/// signs the deploy. When `shell_ecc > 0` the wallet is also credited that much
/// spendable ECC[2] SHELL from the Giver.
#[allow(clippy::too_many_arguments)]
async fn deploy_multisig(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    giver: &GiverClient,
    owners: &[&Keys],
    req_confirms: u8,
    shell_ecc: u128,
    label: &str,
) -> Result<String> {
    let pubkeys: Vec<String> = owners.iter().map(|k| format!("0x{}", k.public)).collect();
    let signer = owners[0];
    let msg = build_deploy(
        ctx,
        MULTISIG_ABI_JSON,
        MULTISIG_TVC,
        json!({}),
        json!({
            "owners_pubkey": pubkeys,
            "owners_address": [],
            "reqConfirms": req_confirms,
            "reqConfirmsData": req_confirms,
            "value": "0",
        }),
        &signer.public,
        &signer.secret,
    )
    .await?;
    eprintln!(
        "{label} ({req_confirms}-of-{}) → {}",
        owners.len(),
        msg.address
    );
    deploy_and_wait(http, reader, cfg, giver, &msg).await?;
    if shell_ecc > 0 {
        giver.send_shell(&msg.address, shell_ecc).await?;
        eprintln!("  funded {label} with {shell_ecc} ECC[2] SHELL");
    }
    Ok(msg.address)
}

/// `submitTransaction` a plain ECC[2] SHELL transfer (empty payload) — used by
/// the treasury to top up the operational wallet's budget. On a 2-of-N treasury
/// this only *queues*; it executes after the required confirmations.
async fn multisig_submit_transfer(
    http: &reqwest::Client,
    wallet: &str,
    signer: &Keys,
    dest: &str,
    shell: u128,
) -> Result<()> {
    let boc = gosh_ackinacki::wallet::transact::encode_external_call(
        wallet,
        &gosh_ackinacki::wallet::contracts::MULTISIG_ABI,
        "submitTransaction",
        &json!({
            "dest": dest,
            "value": GAS_VMSHELL.to_string(),
            "cc": { "2": shell.to_string() },
            "bounce": false,
            "flag": 1,
            "payload": "",
        }),
        &signer.secret,
    )?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(())
}

/// A second custodian confirms a queued treasury transaction.
async fn multisig_confirm(
    http: &reqwest::Client,
    wallet: &str,
    signer: &Keys,
    tx_id: u64,
) -> Result<()> {
    let boc = gosh_ackinacki::wallet::transact::encode_external_call(
        wallet,
        &gosh_ackinacki::wallet::contracts::MULTISIG_ABI,
        "confirmTransaction",
        &json!({ "transactionId": tx_id.to_string() }),
        &signer.secret,
    )?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(())
}

/// The id of the wallet's most recent queued (unexecuted) transaction.
async fn pending_tx_id(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    wallet: &str,
) -> Result<u64> {
    let r = getter(
        reader,
        runner,
        cfg,
        MULTISIG_ABI_JSON,
        wallet,
        "getTransactionIds",
        no_args(),
    )
    .await?;
    let ids = r
        .get("ids")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let last = ids
        .last()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("no queued transaction on {wallet}"))?;
    last.parse::<u64>().map_err(|e| anyhow!("bad tx id: {e}"))
}

// ----- consumer-side escrow ops -----------------------------------------

/// buyTokens(shell): wallet forwards `shell` ECC[2] to TokenContract.buyTokens().
async fn buy_tokens(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    wallet: &str,
    w: &Keys,
    tc: &str,
    shell: u128,
) -> Result<()> {
    let payload = encode_internal_payload(
        ctx,
        Contract::TokenContract.abi_json(),
        "buyTokens",
        json!({}),
    )
    .await?;
    let boc = wallet_forward(
        ctx,
        MULTISIG_ABI_JSON,
        wallet,
        tc,
        GAS_VMSHELL,
        shell,
        true,
        &payload,
        &w.public,
        &w.secret,
    )
    .await?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(())
}

/// cancel(payoutAddress): the buyer's wallet forwards an internal cancel call —
/// refunds the unconsumed reservation and releases the lot lock.
async fn cancel_reservation(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    wallet: &str,
    w: &Keys,
    tc: &str,
    payout: &str,
) -> Result<()> {
    let payload = encode_internal_payload(
        ctx,
        Contract::TokenContract.abi_json(),
        "cancel",
        json!({ "payoutAddress": payout }),
    )
    .await?;
    let boc = wallet_forward(
        ctx,
        MULTISIG_ABI_JSON,
        wallet,
        tc,
        GAS_VMSHELL,
        0,
        true,
        &payload,
        &w.public,
        &w.secret,
    )
    .await?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(())
}

/// consumeSession(n): seller-signed external call.
async fn consume_session(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    tc: &str,
    seller: &Keys,
    sessions: u16,
) -> Result<String> {
    let boc = encode_external_call(
        ctx,
        Contract::TokenContract.abi_json(),
        tc,
        "consumeSession",
        json!({ "sessions": sessions }),
        &seller.public,
        &seller.secret,
    )
    .await?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(boc)
}

/// withdrawShell(amount, recipient): seller-signed external call.
async fn withdraw_shell(
    ctx: &Arc<ClientContext>,
    http: &reqwest::Client,
    tc: &str,
    seller: &Keys,
    amount: u128,
    recipient: &str,
) -> Result<()> {
    let boc = encode_external_call(
        ctx,
        Contract::TokenContract.abi_json(),
        tc,
        "withdrawShell",
        json!({ "amount": amount.to_string(), "recipient": recipient }),
        &seller.public,
        &seller.secret,
    )
    .await?;
    send_message(http, SHELLNET, &boc).await?;
    Ok(())
}

fn is_expected_direct_revert_error(error: &str) -> bool {
    error.contains("TVM_ERROR")
}

/// Drive a call we EXPECT to revert. On this shellnet the Block Manager executes
/// a *direct* external message synchronously and returns the compute-phase
/// failure (`TVM_ERROR`) right on the send, so `send_message` resolves to `Err`.
/// Infrastructure/write-path errors are not valid proof of a contract revert:
/// a halted-chain `QUEUE_OVERFLOW`, timeout, or transport failure would also
/// leave state unchanged while proving only that the write did not reach the
/// contract. Wallet-forwarded calls may return Ok here and bounce on-chain; the
/// following state assertion then remains the proof.
async fn expect_revert<T>(
    label: &str,
    f: impl std::future::Future<Output = Result<T>>,
) -> Result<()> {
    match f.await {
        Err(e) => {
            let msg = e.to_string();
            if is_expected_direct_revert_error(&msg) {
                eprintln!("  (expected direct revert on {label}: {msg})");
                Ok(())
            } else {
                Err(anyhow!(
                    "{label} failed before contract execution, not as an expected revert: {msg}"
                ))
            }
        }
        Ok(_) => {
            eprintln!("  (note: {label} send accepted; revert asserted via state below)");
            Ok(())
        }
    }
}

#[test]
fn expected_revert_classifier_rejects_infrastructure_errors() {
    assert!(is_expected_direct_revert_error(
        "block manager rejected message [TVM_ERROR]: compute phase failed"
    ));
    assert!(!is_expected_direct_revert_error(
        "block manager rejected message [QUEUE_OVERFLOW]: Message queue is full"
    ));
    assert!(!is_expected_direct_revert_error(
        "send MCP HTTP request: operation timed out"
    ));
}

#[tokio::test]
async fn e2e_full_lifecycle() -> Result<()> {
    if std::env::var("GOSH_AIREGISTRY_E2E").is_err() {
        eprintln!("e2e_full_lifecycle: SKIPPED (set GOSH_AIREGISTRY_E2E=1)");
        return Ok(());
    }
    let cfg = AiRegistryConfig::shellnet();
    let http = reqwest::Client::new();
    let reader = AccountReader::new(http.clone(), SHELLNET);
    let runner = GetterRunner::new()?;
    let ctx = local_context()?;
    let giver = GiverClient::new(
        ctx.clone(),
        cfg.giver_address.as_ref().unwrap(),
        cfg.giver_pubkey.as_ref().unwrap(),
        "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b",
        SHELLNET,
        http.clone(),
    );
    // ABIs for GraphQL event decoding (§2.5).
    let tc_abi = Contract::TokenContract.load_abi()?;
    let sr_abi = Contract::SuperRoot.load_abi()?;
    let rm_abi = Contract::RootModel.load_abi()?;

    // ===================== CREATOR =====================
    let sr = Keys::from_secret(SR_SECRET);
    let sr_addr = deploy_super_root(&ctx, &http, &reader, &cfg, &giver, &sr).await?;
    let owner = getter(
        &reader,
        &runner,
        &cfg,
        Contract::SuperRoot.abi_json(),
        &sr_addr,
        "getOwnerPubkey",
        no_args(),
    )
    .await?;
    assert_eq!(
        owner
            .get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_lowercase(),
        format!("0x{}", sr.public).to_lowercase(),
        "SuperRoot owner pubkey mismatch"
    );

    let seller = Keys::from_secret(SELLER_SECRET); // canonical RootModel owner
    let rm_addr = deploy_root_model(&ctx, &http, &reader, &cfg, &giver, &seller, &sr_addr).await?;
    // RootModel address must equal SuperRoot's on-chain derivation.
    let drm = getter(
        &reader,
        &runner,
        &cfg,
        Contract::SuperRoot.abi_json(),
        &sr_addr,
        "getRootModelAddress",
        json!({ "ownerPubkey": format!("0x{}", seller.public) }),
    )
    .await?;
    assert_eq!(
        drm.get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        rm_addr,
        "RootModel derivation mismatch"
    );
    // Event: SuperRoot emits RootRegistered for the new RootModel (§2.5).
    catch_event(&http, &sr_abi, &sr_addr, |e| matches!(e, AiRegistryEvent::RootRegistered { root } if root.trim_start_matches("0:") == rm_addr.trim_start_matches("0:")), "RootRegistered").await?;
    eprintln!("  SuperRoot.getRootModelAddress == RootModel + RootRegistered event ✓");

    // ManifestMetadata: store the FULL canonical package ON-CHAIN — the only
    // source of truth, no off-chain/memory store. The ~127 KB package exceeds a
    // single message, so it goes in as indexed chunks: the constructor's first
    // chunk + `setApiSchemaChunk(idx, chunk)` for the rest. We then read it back
    // via `getApiSchemaChunkCount` + `getApiSchemaChunk(idx)` and assert it
    // reassembles BYTE-FOR-BYTE + matches the pinned sha256 — proving full
    // on-chain availability with zero memory involvement.
    let manifest = Keys::from_secret(MANIFEST_SECRET);
    assert_eq!(
        sha256_hex(SPC_PACKAGE.as_bytes()),
        SPC_PACKAGE_SHA256,
        "vendored SPC fixture sha256 drifted from the pinned constant"
    );
    const MANIFEST_CHUNK: usize = 32 * 1024;
    let chunks = chunk_str(SPC_PACKAGE, MANIFEST_CHUNK);
    assert!(
        chunks.len() >= 2,
        "the {}-byte package must span multiple messages to exercise the досыл path (got {})",
        SPC_PACKAGE.len(),
        chunks.len()
    );
    let mf_msg = build_deploy(
        &ctx,
        Contract::ManifestMetadata.abi_json(),
        Contract::ManifestMetadata.tvc(),
        json!({ "_ownerPubkey": format!("0x{}", manifest.public), "_rootModelAddress": rm_addr, "_superRootAddress": sr_addr }),
        json!({ "firstChunk": chunks[0] }),
        &manifest.public,
        &manifest.secret,
    )
    .await?;
    eprintln!(
        "ManifestMetadata → {} ({} bytes, {} chunks)",
        mf_msg.address,
        SPC_PACKAGE.len(),
        chunks.len()
    );
    deploy_and_wait(&http, &reader, &cfg, &giver, &mf_msg).await?;
    let mf_addr = mf_msg.address.clone();
    // Write the package as indexed chunks via setApiSchemaChunk — each an O(1)
    // write (chunk mapping, not a growing string), so the full 127 KB fits with
    // no gas cap. A rapid external send can be accepted by /v2/messages yet drop
    // (no tx produced) — and a reused manifest may carry a stale same-length
    // chunk — so confirm each chunk by EXACT CONTENT and RESEND the idempotent
    // setApiSchemaChunk until it lands (mirrors the MCP `set_manifest` tool's
    // `mf_apply_chunk`). This keeps the test robust as shellnet changes.
    let mf_abi = Contract::ManifestMetadata.abi_json();
    for (i, c) in chunks.iter().enumerate() {
        let mut landed = false;
        let mut last_send_err: Option<String> = None;
        for _attempt in 0..6 {
            let boc = encode_external_call(
                &ctx,
                mf_abi,
                &mf_addr,
                "setApiSchemaChunk",
                json!({ "idx": i, "chunk": c }),
                &manifest.public,
                &manifest.secret,
            )
            .await?;
            // A BM refusal (e.g. QUEUE_OVERFLOW on a stalled chain) now surfaces
            // as Err — record it and retry the idempotent send rather than
            // aborting; a genuinely halted chain is diagnosed below.
            if let Err(e) = send_message(&http, SHELLNET, &boc).await {
                last_send_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
            last_send_err = None;
            let attempt_deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let r = getter(
                    &reader,
                    &runner,
                    &cfg,
                    mf_abi,
                    &mf_addr,
                    "getApiSchemaChunk",
                    json!({ "idx": i }),
                )
                .await?;
                let got = r.get("value0").and_then(|v| v.as_str()).unwrap_or("");
                if got == *c {
                    landed = true;
                    break;
                }
                if Instant::now() > attempt_deadline {
                    break; // timed out this attempt → resend (idempotent)
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            if landed {
                break;
            }
        }
        if !landed {
            // Tell "our write is broken" apart from "shellnet is down": probe
            // block production. A stale tip (>60s) means the chain is halted and
            // every write is being rejected with QUEUE_OVERFLOW — not our bug.
            let diag = match reader.chain_liveness(60).await {
                Ok(l) if !l.is_live() => format!(
                    "chain HALTED — newest block #{} is {}s old (>{}s); writes rejected with QUEUE_OVERFLOW",
                    l.latest_seq_no, l.latest_block_age_secs, l.stale_after_secs
                ),
                Ok(l) => format!(
                    "chain live (newest block {}s old) — write genuinely failed",
                    l.latest_block_age_secs
                ),
                Err(e) => format!("chain liveness probe failed: {e}"),
            };
            panic!(
                "setApiSchemaChunk {i} did not land after retries ({} bytes); last send error: {last_send_err:?}; {diag}",
                c.len()
            );
        }
    }
    eprintln!("    package written on-chain: {} chunks", chunks.len());
    let dmf = getter(
        &reader,
        &runner,
        &cfg,
        Contract::SuperRoot.abi_json(),
        &sr_addr,
        "getManifestAddress",
        json!({ "ownerPubkey": format!("0x{}", manifest.public), "rootModelAddress": rm_addr }),
    )
    .await?;
    assert_eq!(
        dmf.get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        mf_addr,
        "Manifest derivation mismatch"
    );
    // Read the FULL package back from chain: chunk count, then each chunk in
    // order, concatenated — prove byte-exact reassembly.
    let cnt = getter(
        &reader,
        &runner,
        &cfg,
        mf_abi,
        &mf_addr,
        "getApiSchemaChunkCount",
        no_args(),
    )
    .await?;
    let count: u32 = cnt
        .get("value0")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(
        count as usize,
        chunks.len(),
        "on-chain chunk count mismatch"
    );
    let mut stored = String::new();
    for idx in 0..count {
        let r = getter(
            &reader,
            &runner,
            &cfg,
            mf_abi,
            &mf_addr,
            "getApiSchemaChunk",
            json!({ "idx": idx }),
        )
        .await?;
        stored.push_str(r.get("value0").and_then(|v| v.as_str()).unwrap_or_default());
    }
    assert_eq!(
        stored.len(),
        SPC_PACKAGE.len(),
        "on-chain package length mismatch — chunk reassembly failed"
    );
    assert_eq!(
        stored, SPC_PACKAGE,
        "on-chain package is not byte-identical to the source"
    );
    assert_eq!(
        sha256_hex(stored.as_bytes()),
        SPC_PACKAGE_SHA256,
        "on-chain package sha256 must equal the pinned hash"
    );
    assert_eq!(
        stored.lines().count(),
        144,
        "the full 144-record package must round-trip from chain"
    );
    let sha_prefix: String = SPC_PACKAGE_SHA256.chars().take(12).collect();
    // Event: SuperRoot emits ManifestRegistered (§2.5).
    catch_event(&http, &sr_abi, &sr_addr, |e| matches!(e, AiRegistryEvent::ManifestRegistered { manifest } if manifest.trim_start_matches("0:") == mf_addr.trim_start_matches("0:")), "ManifestRegistered").await?;
    eprintln!(
        "  ManifestMetadata: FULL {}-byte package stored ON-CHAIN in {} chunks, read back byte-exact (sha256 {sha_prefix}…) + ManifestRegistered ✓",
        SPC_PACKAGE.len(),
        count
    );

    // TokenContract #1 (the token lot for the positive flow). The lot seller is
    // FRESH per run (canonical `seller` owns the reusable RootModel; the lots
    // themselves must be pristine for the escrow assertions).
    let s1 = gen_keys();
    let tc1 =
        deploy_token_contract(&ctx, &http, &reader, &cfg, &giver, &s1, &rm_addr, 1, 10, 0).await?;
    let drtc = getter(
        &reader,
        &runner,
        &cfg,
        Contract::RootModel.abi_json(),
        &rm_addr,
        "getTokenContractAddress",
        json!({ "sellerPubkey": format!("0x{}", s1.public), "nonce": "1" }),
    )
    .await?;
    assert_eq!(
        drtc.get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        tc1,
        "TokenContract derivation mismatch"
    );
    // Event: RootModel emits TokenContractRegistered (§2.5).
    catch_event(&http, &rm_abi, &rm_addr, |e| matches!(e, AiRegistryEvent::TokenContractRegistered { token } if token.trim_start_matches("0:") == tc1.trim_start_matches("0:")), "TokenContractRegistered").await?;
    let s = token_state(&reader, &runner, &cfg, &tc1).await?;
    assert_eq!(
        (s.available, s.sold, s.reserved),
        (10, 0, 0),
        "fresh TokenContract counters: {s:?}"
    );
    eprintln!("  RootModel.getTokenContractAddress == TokenContract, available=10 ✓");

    // ===================== CONSUMER (positive) =====================
    let wallet_keys = Keys::from_secret(CONSUMER_SECRET);
    let wallet = deploy_multisig(
        &ctx,
        &http,
        &reader,
        &cfg,
        &giver,
        &[&wallet_keys],
        1,
        3_000,
        "ConsumerWallet",
    )
    .await?;

    // buyTokens(6): pay 6 ECC[2] SHELL → reserved=6, sold=6, available=4, locked.
    buy_tokens(&ctx, &http, &wallet, &wallet_keys, &tc1, 6).await?;
    let s = wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc1,
        |t| t.reserved == 6 && t.sold == 6,
        "reserved=6 after buy",
    )
    .await?;
    assert_eq!((s.available, s.shell), (4, 6), "after buy: {s:?}");
    assert_eq!(
        s.buyer.trim_start_matches("0:"),
        wallet.trim_start_matches("0:"),
        "currentBuyer != wallet"
    );
    catch_event(
        &http,
        &tc_abi,
        &tc1,
        |e| {
            matches!(
                e,
                AiRegistryEvent::TokensPurchased {
                    amount: 6,
                    fee: 0,
                    ..
                }
            )
        },
        "TokensPurchased(6)",
    )
    .await?;
    eprintln!(
        "  buyTokens(6 SHELL): reserved=6, sold=6, shell=6, locked + TokensPurchased event ✓"
    );

    // Stateless user-signed PAYMENTS (Flow A) against this live ACTIVE lot, where
    // `wallet` is the current buyer with reserved=6: the tools encode an inner
    // payload + verify readiness from chain, with no Memory and no keys.
    {
        use gosh_ackinacki::mcp::tools::call_tool;
        use gosh_ackinacki::state::AppState;
        let sp =
            AppState::new_stateless_payments(gosh_ackinacki::config::NetworkConfig::shellnet());
        // prepare_user_buy_tokens: real inner buyTokens payload + populated preflight.
        let buy = call_tool(
            &sp,
            "airegistry_prepare_user_buy_tokens",
            json!({ "token_contract_address": tc1, "buyer_wallet_address": wallet, "shell_amount": "6000000000" }),
        )
        .await?;
        assert_eq!(buy["intent"]["method"], "buyTokens");
        assert_eq!(buy["intent"]["flow"], "payload_only");
        assert!(
            buy["intent"]["payload_boc_b64"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "buyTokens payload must be present"
        );
        // wallet_action carries the explicit ECC[2] SHELL + gas + body the wallet
        // must attach (buyTokens has no payload amount).
        assert_eq!(buy["wallet_action"]["to"].as_str(), Some(tc1.as_str()));
        assert_eq!(buy["wallet_action"]["shell_amount"], "6000000000");
        assert_eq!(
            buy["wallet_action"]["required_capability"],
            "transfer_with_custom_body"
        );
        assert!(
            !buy["preflight"]["lot"].is_null(),
            "preflight lot must be populated for an active lot"
        );
        // verify_payment_readiness: the current buyer with reserved≥1 ⇒ verified.
        // It is a pure read, so it must also work in --read-only mode.
        let ro = AppState::new_read_only(gosh_ackinacki::config::NetworkConfig::shellnet());
        let vr = call_tool(
            &ro,
            "airegistry_verify_payment_readiness",
            json!({ "token_contract_address": tc1, "buyer_wallet_address": wallet }),
        )
        .await?;
        assert_eq!(vr["ready"], json!(true), "readiness: {vr}");
        assert_eq!(vr["status"], "verified");
        assert_eq!(vr["entitlement"]["is_current_buyer"], json!(true));
        assert!(vr["checked_at"].as_str().is_some_and(|s| !s.is_empty()));
        // prepare_user_cancel: payout is fixed to the buyer wallet.
        let cancel = call_tool(
            &sp,
            "airegistry_prepare_user_cancel",
            json!({ "token_contract_address": tc1, "buyer_wallet_address": wallet }),
        )
        .await?;
        assert_eq!(
            cancel["intent"]["payout_wallet_address"].as_str(),
            Some(wallet.as_str())
        );
        // Key material is refused outright.
        assert!(call_tool(
            &sp,
            "airegistry_prepare_user_cancel",
            json!({ "token_contract_address": tc1, "buyer_wallet_address": wallet, "secret": "x" }),
        )
        .await
        .is_err());
        eprintln!("  STATELESS PAYMENTS (Flow A): buyTokens payload + readiness=verified + cancel payout=buyer + key-guard ✓");
    }

    // seller consumeSession(3) → FIRST batch (≤ maxReservedSessions=3): bills 3
    // sessions straight into sellerOwed (no buyer confirmation). reserved 6→3.
    consume_session(&ctx, &http, &tc1, &s1, 3).await?;
    wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc1,
        |t| t.reserved == 3 && t.seller_owed == 3 && t.consume_calls == 1,
        "first batch consume(3)",
    )
    .await?;
    catch_event(
        &http,
        &tc_abi,
        &tc1,
        |e| matches!(e, AiRegistryEvent::TokensConsumed { sessions: 3, .. }),
        "TokensConsumed(3)",
    )
    .await?;
    eprintln!("  consumeSession(3) first batch: reserved=3, sellerOwed=3 + TokensConsumed event ✓");

    // seller consumeSession(2) → MUST be blocked: after the first batch every call
    // must take exactly one session (ERR_SINGLE_SESSION_REQUIRED). This direct
    // seller call reverts; the BM returns the compute failure synchronously, so
    // `expect_revert` tolerates the Err and the unchanged state below is the proof.
    expect_revert(
        "consumeSession(2) single-session",
        consume_session(&ctx, &http, &tc1, &s1, 2),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    let s = token_state(&reader, &runner, &cfg, &tc1).await?;
    assert_eq!(
        (s.reserved, s.seller_owed, s.consume_calls),
        (3, 3, 1),
        "post-first-batch multi-session consume must be rejected: {s:?}"
    );
    eprintln!("  consumeSession(2) after first batch: correctly blocked (single-session rule) ✓");

    // seller bills the remaining 3 one session at a time; the LAST drains reserved
    // to 0 and auto-releases the lot (currentBuyer cleared, consumeCalls reset).
    for i in 1..=3u128 {
        consume_session(&ctx, &http, &tc1, &s1, 1).await?;
        let target = 3 - i;
        wait_tc(
            &reader,
            &runner,
            &cfg,
            &tc1,
            move |t| t.reserved == target && t.seller_owed == 3 + i,
            "single-session consume",
        )
        .await?;
    }
    let s = wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc1,
        |t| t.reserved == 0 && t.seller_owed == 6 && is_zero_addr(&t.buyer),
        "drained + auto-released",
    )
    .await?;
    assert_eq!(
        s.consume_calls, 0,
        "auto-release resets consumeCalls: {s:?}"
    );
    eprintln!("  consumeSession(1)×3: reserved=0, sellerOwed=6, lot auto-released ✓");

    // seller withdrawShell(6): the contract SHELL balance must drain AND the
    // recipient must actually receive the ECC[2] — assert the payout sink's
    // SHELL balance rises by exactly the withdrawn amount, not just that the
    // contract hit zero (which a misrouted/lost withdrawal would also satisfy).
    let sink_before = ecc_balance(&http, &rm_addr, 2).await?;
    withdraw_shell(&ctx, &http, &tc1, &s1, 6, &rm_addr).await?;
    wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc1,
        |t| t.shell == 0,
        "shell balance drained",
    )
    .await?;
    // Give the value transfer a moment to land at the recipient, then poll.
    let mut sink_after = ecc_balance(&http, &rm_addr, 2).await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while sink_after < sink_before + 6 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        sink_after = ecc_balance(&http, &rm_addr, 2).await?;
    }
    assert_eq!(
        sink_after - sink_before,
        6,
        "withdrawShell must credit the recipient ECC[2] by 6 (before={sink_before}, after={sink_after})"
    );
    catch_event(
        &http,
        &tc_abi,
        &tc1,
        |e| matches!(e, AiRegistryEvent::ShellWithdrawn { amount: 6, .. }),
        "ShellWithdrawn(6)",
    )
    .await?;
    eprintln!("  withdrawShell(6): contract drained, recipient +6 SHELL + ShellWithdrawn event ✓");

    // ===================== NEGATIVE: under-delivery → buyer cancels =====================
    // A fresh token lot. The model under-delivers: the seller bills its first
    // batch, then the buyer CANCELS to refund the unconsumed reservation and
    // release the lot. The seller keeps only what it already billed (sellerOwed);
    // the buyer gets the unconsumed SHELL back; an over-budget buy still aborts.
    eprintln!("== NEGATIVE: under-delivery → buyer cancels remainder ==");
    let seller2 = gen_keys();
    let tc2 = deploy_token_contract(
        &ctx, &http, &reader, &cfg, &giver, &seller2, &rm_addr, 2, 5, 0,
    )
    .await?;

    // buyer buys a small budget (4 of the 5 available).
    buy_tokens(&ctx, &http, &wallet, &wallet_keys, &tc2, 4).await?;
    wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc2,
        |t| t.reserved == 4,
        "neg: reserved=4",
    )
    .await?;
    eprintln!("  buyer bought a 4-SHELL budget ✓");

    // seller bills its first batch (3 of 4) → 3 SHELL becomes sellerOwed, reserved=1.
    consume_session(&ctx, &http, &tc2, &seller2, 3).await?;
    wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc2,
        |t| t.reserved == 1 && t.seller_owed == 3,
        "neg: first batch billed 3",
    )
    .await?;

    // SAFETY (prepaid-streaming invariant): withdrawShell is bounded by
    // sellerOwed (3), NOT the contract's SHELL balance (4 = 3 owed + 1 still
    // reserved for the buyer). A malicious withdrawShell(4) must abort and neither
    // credit the recipient nor move state. This direct seller call reverts
    // (`require(amount <= _sellerOwed)`); the unchanged recipient balance +
    // counters below are the proof.
    let owed_sink_before = ecc_balance(&http, &rm_addr, 2).await?;
    let pre = token_state(&reader, &runner, &cfg, &tc2).await?;
    expect_revert(
        "withdrawShell(4) > sellerOwed(3)",
        withdraw_shell(&ctx, &http, &tc2, &seller2, 4, &rm_addr),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let post = token_state(&reader, &runner, &cfg, &tc2).await?;
    assert_eq!(
        ecc_balance(&http, &rm_addr, 2).await?,
        owed_sink_before,
        "neg: over-withdraw (4 > sellerOwed 3) must not credit the recipient"
    );
    assert_eq!(
        (post.seller_owed, post.shell, post.reserved),
        (pre.seller_owed, pre.shell, pre.reserved),
        "neg: over-withdraw must not move state: {post:?}"
    );
    eprintln!(
        "  withdrawShell(4) > sellerOwed(3): rejected (recipient not credited, state intact) ✓"
    );

    // buyer CANCELS → the 1 unconsumed reserved SHELL is refunded to the buyer
    // wallet, the lot unlocks, and sellerOwed (3) is preserved for the seller.
    let buyer_before = ecc_balance(&http, &wallet, 2).await?;
    cancel_reservation(&ctx, &http, &wallet, &wallet_keys, &tc2, &wallet).await?;
    let s = wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc2,
        |t| t.reserved == 0 && is_zero_addr(&t.buyer),
        "neg: cancelled + unlocked",
    )
    .await?;
    assert_eq!(
        s.seller_owed, 3,
        "neg: seller keeps the 3 sessions it billed: {s:?}"
    );
    catch_event(
        &http,
        &tc_abi,
        &tc2,
        |e| matches!(e, AiRegistryEvent::ReservationCancelled { refunded: 1, .. }),
        "ReservationCancelled(1)",
    )
    .await?;
    // the buyer actually received the 1 unconsumed SHELL back (ECC carries no gas).
    let mut buyer_after = ecc_balance(&http, &wallet, 2).await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while buyer_after < buyer_before + 1 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        buyer_after = ecc_balance(&http, &wallet, 2).await?;
    }
    assert_eq!(buyer_after - buyer_before, 1, "neg: cancel must refund the 1 unconsumed SHELL (before={buyer_before}, after={buyer_after})");
    eprintln!("  buyer cancelled: 1 SHELL refunded, lot unlocked, seller keeps 3 billed ✓");

    // The seller CAN now withdraw EXACTLY what it billed (3) — sellerOwed
    // survives cancel and is fully covered by the contract's SHELL balance.
    let paid_before = ecc_balance(&http, &rm_addr, 2).await?;
    withdraw_shell(&ctx, &http, &tc2, &seller2, 3, &rm_addr).await?;
    wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc2,
        |t| t.seller_owed == 0 && t.shell == 0,
        "neg: seller withdrew its 3 billed",
    )
    .await?;
    let mut paid_after = ecc_balance(&http, &rm_addr, 2).await?;
    let deadline2 = Instant::now() + Duration::from_secs(60);
    while paid_after < paid_before + 3 && Instant::now() < deadline2 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        paid_after = ecc_balance(&http, &rm_addr, 2).await?;
    }
    assert_eq!(
        paid_after - paid_before,
        3,
        "neg: post-cancel withdrawShell(3) must credit the seller exactly 3"
    );
    eprintln!("  withdrawShell(3) == sellerOwed: succeeds, recipient +3 ✓");

    // buyer STOPS — an over-budget buy (10 vs availability) aborts. The forward
    // is bounceable, so no SHELL must leave the wallet and none must stick to
    // the contract: assert the contract counters AND shell balance are
    // unchanged, and the wallet's ECC[2] balance is restored by the bounce.
    let before = token_state(&reader, &runner, &cfg, &tc2).await?;
    let wallet_shell_before = ecc_balance(&http, &wallet, 2).await?;
    buy_tokens(&ctx, &http, &wallet, &wallet_keys, &tc2, 10).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let after = token_state(&reader, &runner, &cfg, &tc2).await?;
    assert_eq!(
        after.sold, before.sold,
        "neg: over-budget buy must not sell tokens: {after:?}"
    );
    assert_eq!(
        after.reserved, before.reserved,
        "neg: over-budget buy must not reserve: {after:?}"
    );
    assert_eq!(
        after.shell, before.shell,
        "neg: aborted buy must not stick SHELL to the contract: {after:?}"
    );
    // The bounce returns the ECC[2] to the wallet (ECC carries no gas fee — gas
    // is paid in native VMSHELL), so the wallet's SHELL must settle back to
    // exactly its pre-attempt level. Poll for the in-flight bounce to land.
    let mut wallet_shell_after = ecc_balance(&http, &wallet, 2).await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while wallet_shell_after < wallet_shell_before && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        wallet_shell_after = ecc_balance(&http, &wallet, 2).await?;
    }
    assert_eq!(
        wallet_shell_after, wallet_shell_before,
        "neg: aborted buy must leave the wallet SHELL unchanged (no payment leaves the wallet)"
    );
    eprintln!("  over-budget buy aborted: no tokens sold, contract SHELL flat, wallet refunded ✓");

    // ===================== BUDGET DELEGATION: 2-of-3 treasury → 1-sig operational =====================
    // The defining consumer model (spec §2.4): a governed 2-of-3 treasury holds
    // the funds and a 1-sig operational wallet spends a delegated budget. This
    // exercises BOTH signing modes and proves the 2-of-3 cap is real — a single
    // custodian cannot move the treasury's budget.
    eprintln!("== BUDGET DELEGATION: 2-of-3 treasury governs a 1-sig operational budget ==");
    let (t1, t2, t3) = (
        Keys::from_secret(T1_SECRET),
        Keys::from_secret(T2_SECRET),
        Keys::from_secret(T3_SECRET),
    );
    let treasury = deploy_multisig(
        &ctx,
        &http,
        &reader,
        &cfg,
        &giver,
        &[&t1, &t2, &t3],
        2,
        100,
        "Treasury",
    )
    .await?;
    let (o1, o2, o3) = (
        Keys::from_secret(O1_SECRET),
        Keys::from_secret(O2_SECRET),
        Keys::from_secret(O3_SECRET),
    );
    let operational = deploy_multisig(
        &ctx,
        &http,
        &reader,
        &cfg,
        &giver,
        &[&o1, &o2, &o3],
        1,
        0,
        "Operational",
    )
    .await?;

    // Governed top-up: custodian #1 submits a 60-SHELL budget transfer. With
    // reqConfirms=2 this only QUEUES — the operational wallet must NOT receive it.
    let oper_before = ecc_balance(&http, &operational, 2).await?;
    multisig_submit_transfer(&http, &treasury, &t1, &operational, 60).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let oper_mid = ecc_balance(&http, &operational, 2).await?;
    assert_eq!(
        oper_mid, oper_before,
        "governance bypass: a single custodian must NOT move the treasury budget (got {oper_mid}, was {oper_before})"
    );
    eprintln!("  1 custodian submitted → budget QUEUED, operational still unfunded (2-of-3 not bypassable) ✓");

    // Second custodian confirms → the 2-of-3 threshold is met → the transfer fires.
    let tx_id = pending_tx_id(&reader, &runner, &cfg, &treasury).await?;
    multisig_confirm(&http, &treasury, &t2, tx_id).await?;
    let mut oper_after = ecc_balance(&http, &operational, 2).await?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while oper_after < oper_before + 60 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        oper_after = ecc_balance(&http, &operational, 2).await?;
    }
    assert_eq!(
        oper_after - oper_before,
        60,
        "the 2nd confirmation must release the 60-SHELL budget"
    );
    eprintln!("  2nd custodian confirmed (tx {tx_id}) → operational funded with 60 SHELL ✓");

    // 1-sig path: the operational wallet autonomously spends its delegated budget.
    let seller3 = gen_keys();
    let tc3 = deploy_token_contract(
        &ctx, &http, &reader, &cfg, &giver, &seller3, &rm_addr, 3, 50, 0,
    )
    .await?;
    buy_tokens(&ctx, &http, &operational, &o1, &tc3, 30).await?;
    let s = wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc3,
        |t| t.reserved == 30 && t.sold == 30,
        "oper buy reserved=30",
    )
    .await?;
    assert_eq!(
        s.buyer.trim_start_matches("0:"),
        operational.trim_start_matches("0:"),
        "currentBuyer must be the operational wallet"
    );
    let _ = (&t3, &o2, &o3); // remaining custodians are real signers, just unused in this path
    eprintln!("  operational (1-sig) bought 30 tokens from its delegated budget ✓");

    // ===================== NEGATIVE: fee/burn, lock-conflict, code-hash lock =====================
    eprintln!("== NEGATIVE: fee/burn, lock-conflict, code-hash lock ==");

    // (a) Fee burn. A lot with burnFeeBps=250 (2.5%). buyTokens computes
    // fee = paid*bps/10000 and `gosh.burnecc`s it, crediting amount = paid-fee.
    // Pay 1000 → fee=25 burned, 975 credited ⇒ sold==reserved==shellBalance==975.
    let seller_fee = gen_keys();
    let tc_fee = deploy_token_contract(
        &ctx,
        &http,
        &reader,
        &cfg,
        &giver,
        &seller_fee,
        &rm_addr,
        4,
        2000,
        250,
    )
    .await?;
    buy_tokens(&ctx, &http, &wallet, &wallet_keys, &tc_fee, 1_000).await?;
    let s = wait_tc(
        &reader,
        &runner,
        &cfg,
        &tc_fee,
        |t| t.sold == 975,
        "fee: sold=975",
    )
    .await?;
    assert_eq!(
        s.reserved, 975,
        "fee/burn: reserved must be paid-fee=975: {s:?}"
    );
    assert_eq!(
        s.shell, 975,
        "fee/burn: contract must hold paid-fee=975 (25 SHELL burned): {s:?}"
    );
    catch_event(
        &http,
        &tc_abi,
        &tc_fee,
        |e| matches!(e, AiRegistryEvent::FeeBurned { amount: 25 }),
        "FeeBurned(25)",
    )
    .await?;
    catch_event(
        &http,
        &tc_abi,
        &tc_fee,
        |e| {
            matches!(
                e,
                AiRegistryEvent::TokensPurchased {
                    amount: 975,
                    fee: 25,
                    ..
                }
            )
        },
        "TokensPurchased(975,fee=25)",
    )
    .await?;
    eprintln!("  fee/burn: paid 1000 → 25 burned, 975 reserved + held + FeeBurned/TokensPurchased events ✓");

    // (b) Lock conflict. tc_fee is now locked to `wallet`. The `operational`
    // wallet tries to buy the SAME lot → ERR_CONTRACT_LOCKED; the lot stays
    // locked to the first buyer, sells nothing more, and the rejected buyer's
    // SHELL bounces back to it.
    let oper_shell_before = ecc_balance(&http, &operational, 2).await?;
    let lock_before = token_state(&reader, &runner, &cfg, &tc_fee).await?;
    buy_tokens(&ctx, &http, &operational, &o1, &tc_fee, 10).await?;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let lock_after = token_state(&reader, &runner, &cfg, &tc_fee).await?;
    assert_eq!(
        lock_after.buyer.trim_start_matches("0:"),
        wallet.trim_start_matches("0:"),
        "lock-conflict: lot must stay locked to the first buyer: {lock_after:?}"
    );
    assert_eq!(
        lock_after.sold, lock_before.sold,
        "lock-conflict: a locked lot must not sell to a second buyer"
    );
    let mut oper_shell_after = ecc_balance(&http, &operational, 2).await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while oper_shell_after < oper_shell_before && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(3)).await;
        oper_shell_after = ecc_balance(&http, &operational, 2).await?;
    }
    assert_eq!(
        oper_shell_after, oper_shell_before,
        "lock-conflict: the rejected buyer's SHELL must bounce back"
    );
    eprintln!("  lock-conflict: 2nd wallet rejected (lot stays locked), its SHELL refunded ✓");

    // (c) Code-hash lock. A SuperRoot deployed with a WRONG rootModelCode must
    // abort in its constructor (require tvm.hash(rootModelCode)==ROOT_MODEL_CODE_HASH,
    // ERR_BAD_CODE_HASH) and never become a working SuperRoot.
    let bad = gen_keys();
    let wrong_root_code = Contract::TokenContract.code_boc_b64()?; // NOT the RootModel code
    let mf_code = Contract::ManifestMetadata.code_boc_b64()?;
    let bad_msg = build_deploy(
        &ctx,
        Contract::SuperRoot.abi_json(),
        Contract::SuperRoot.tvc(),
        json!({}),
        json!({ "pubkey": format!("0x{}", bad.public), "rootModelCode": wrong_root_code, "manifestCode": mf_code }),
        &bad.public,
        &bad.secret,
    )
    .await?;
    giver
        .fund_deploy_address(&bad_msg.address, DEPLOY_FUND)
        .await?;
    wait_status(&reader, &cfg, &bad_msg.address, "Uninit").await?;
    expect_revert(
        "bad-code SuperRoot deploy",
        send_message(&http, SHELLNET, &bad_msg.message_boc_b64),
    )
    .await?;
    // The bad-code constructor must reject: the account never reaches a working
    // SuperRoot. Wait out a window, then assert it is not a functioning contract.
    tokio::time::sleep(Duration::from_secs(18)).await;
    let bad_snap = reader
        .fetch(&cfg, &bad_msg.address, &AccountOrigin::SelfOriginating)
        .await?;
    let bad_acc = bad_snap
        .as_ref()
        .map(|s| s.acc_type_name.as_str())
        .unwrap_or("NotFound");
    let initialized_ok = if bad_acc == "Active" {
        // If it somehow went Active, prove the constructor never ran by checking
        // the owner pubkey wasn't set to the bad key.
        match getter(
            &reader,
            &runner,
            &cfg,
            Contract::SuperRoot.abi_json(),
            &bad_msg.address,
            "getOwnerPubkey",
            no_args(),
        )
        .await
        {
            Ok(v) => {
                v.get("value0")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_lowercase())
                    == Some(format!("0x{}", bad.public).to_lowercase())
            }
            Err(_) => false,
        }
    } else {
        false
    };
    assert!(
        !initialized_ok,
        "code-hash lock: SuperRoot with a wrong rootModelCode must NOT become a working contract (acc={bad_acc})"
    );
    eprintln!("  code-hash lock: SuperRoot with wrong rootModelCode rejected (acc={bad_acc}) ✓");

    eprintln!(
        "\n=== AIREGISTRY FULL LIFECYCLE + NEGATIVES + BUDGET DELEGATION + EVENTS PASSED ==="
    );
    Ok(())
}
