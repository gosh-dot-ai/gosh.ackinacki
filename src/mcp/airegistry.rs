// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! airegistry (SPC token marketplace) MCP tool surface (§9).
//!
//! Generic (§9.1): `call_contract` (read getter, or signed ext-in write when a
//! `signer_ref` is given), `deploy_contract`.
//!
//! Creator (§9.2) — the model vendor, signing with a `signer_ref` seller key:
//! `airegistry_deploy_super_root`, `_register_model`, `_set_manifest`,
//! `_create_token_lot`, `_bill_session`, `_replenish`, `_set_endpoint`,
//! `_withdraw_shell`, `_destroy_lot`, `_get_lot`.
//!
//! Consumer (§9.3) — acting through 3-custodian `SwarmMultisigWallet`s (treasury
//! reqConfirms=2, operational reqConfirms=1), signing with named wallet custodian
//! keys: `airegistry_resolve_model`, `_deploy_buyer`, `_fund_buyer`,
//! `_buy_tokens`, `_cancel`, `_get_entitlement`.
//!
//! Deploys are funded on shellnet by the configured Giver (§8); each write tool
//! persists its address/metadata pointer to the object store (§10); on-chain
//! reverts are mapped to readable `ERR_*` messages (§11).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use tvm_client::ClientContext;

use super::tools::{
    enforce_wallet_policy, get_wallet_key_value, parse_address, validate_signer_role,
    validate_wallet_id, WALLET_METADATA_KIND, WALLET_PRIVKEY_KIND, WALLET_PUBKEY_KIND,
};
use crate::airegistry::abi::Contract;
use crate::airegistry::calls::{encode_external_call, encode_internal_payload, wallet_forward};
use crate::airegistry::deploy::{build_deploy, local_context};
use crate::airegistry::errors::check_send_response;
use crate::airegistry::events::AiRegistryEvent;
use crate::airegistry::getter::{AccountOrigin, AccountReader};
use crate::airegistry::run::GetterRunner;
use crate::airegistry::signer::{Signer, SignerRef};
use crate::airegistry::store::{Store, KIND_OPER_WALLET};
use crate::config::AiRegistryConfig;
use crate::state::AppState;
use crate::wallet;
use crate::wallet::contracts::MULTISIG_ABI_JSON;
use crate::wallet::giver::GiverClient;

const AIREGISTRY_GAS_VMSHELL: u128 = 1_000_000_000;
const DEPLOY_FUND_VMSHELL: u128 = 200_000_000_000;

// ----- arg helpers -------------------------------------------------------

fn contract_by_name(name: &str) -> Result<Contract> {
    match name {
        "SuperRoot" => Ok(Contract::SuperRoot),
        "RootModel" => Ok(Contract::RootModel),
        "TokenContract" => Ok(Contract::TokenContract),
        "ManifestMetadata" => Ok(Contract::ManifestMetadata),
        _ => bail!("unknown airegistry contract '{name}'"),
    }
}

fn resolve_abi(args: &Value) -> Result<String> {
    if let Some(name) = args.get("contract").and_then(|v| v.as_str()) {
        return Ok(contract_by_name(name)?.abi_json().to_string());
    }
    if let Some(abi) = args.get("abi_json").and_then(|v| v.as_str()) {
        return Ok(abi.to_string());
    }
    bail!("provide either `contract` (airegistry name) or `abi_json`")
}

fn resolve_tvc(args: &Value) -> Result<Vec<u8>> {
    if let Some(name) = args.get("contract").and_then(|v| v.as_str()) {
        return Ok(contract_by_name(name)?.tvc().to_vec());
    }
    if let Some(b64) = args
        .get("tvc_b64")
        .or_else(|| args.get("code_boc"))
        .and_then(|v| v.as_str())
    {
        use base64::Engine;
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| anyhow!("decode tvc/code_boc: {e}"));
    }
    bail!("provide `contract`, or `abi_json` + `tvc_b64`")
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    match args.get(key).and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => bail!("`{key}` is required"),
    }
}

fn opt_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn req_u128(args: &Value, key: &str) -> Result<u128> {
    match args.get(key) {
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| anyhow!("`{key}` not an integer: {s}")),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| anyhow!("`{key}` not a non-negative integer")),
        _ => bail!("`{key}` is required"),
    }
}

fn req_u16(args: &Value, key: &str) -> Result<u16> {
    let v = req_u128(args, key)?;
    u16::try_from(v).map_err(|_| anyhow!("`{key}` out of range for uint16: {v}"))
}

fn req_u64(args: &Value, key: &str) -> Result<u64> {
    let v = req_u128(args, key)?;
    u64::try_from(v).map_err(|_| anyhow!("`{key}` out of range for uint64: {v}"))
}

fn req_u8(args: &Value, key: &str) -> Result<u8> {
    let v = req_u128(args, key)?;
    u8::try_from(v).map_err(|_| anyhow!("`{key}` out of range for uint8: {v}"))
}

/// Fold a §10 pointer-persistence outcome into a tool response: `persisted:
/// true`, or `persisted: false` + `persist_warning`. The deployed on-chain
/// address is never lost to a transient memory failure (the agent still gets it
/// and can re-issue / pass the address explicitly), but the failure is surfaced
/// rather than silently dropped with `.ok()`.
fn fold_persist(mut out: Value, persist: Result<()>) -> Value {
    match persist {
        Ok(()) => out["persisted"] = json!(true),
        Err(e) => {
            out["persisted"] = json!(false);
            out["persist_warning"] = json!(e.to_string());
        }
    }
    out
}

fn hexparam(pubkey: &str) -> String {
    let p = pubkey.trim().trim_start_matches("0x");
    format!("0x{p}")
}

fn origin_for(args: &Value, cfg: &AiRegistryConfig) -> AccountOrigin {
    match opt_str(args, "dapp_id")
        .map(String::from)
        .or_else(|| cfg.dapp_id_override.clone())
    {
        Some(d) => AccountOrigin::Explicit { dapp_id: d },
        None => AccountOrigin::SelfOriginating,
    }
}

// ----- shared chain helpers ---------------------------------------------

fn reader(state: &AppState) -> AccountReader {
    AccountReader::new(state.http.clone(), &state.network.send_endpoint)
}

/// Run a read-only getter over the account's live BOC.
async fn getter_read(
    state: &AppState,
    abi: &str,
    addr: &str,
    method: &str,
    params: Value,
    origin: &AccountOrigin,
) -> Result<Value> {
    let snap = reader(state)
        .fetch(&state.network.airegistry, addr, origin)
        .await?
        .ok_or_else(|| anyhow!("account {addr} not found / not active"))?;
    let boc = snap
        .boc
        .as_ref()
        .ok_or_else(|| anyhow!("account {addr} returned no BOC"))?;
    GetterRunner::new()?
        .run_getter(abi, addr, boc, method, params)
        .await
}

async fn wait_status(
    reader: &AccountReader,
    cfg: &AiRegistryConfig,
    addr: &str,
    target: &str,
    secs: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(secs);
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

/// Fund a fresh derived deploy address via the configured Giver (§8). Errors on
/// networks with no Giver (mainnet) — those fund out-of-band.
async fn fund_via_giver(state: &AppState, ctx: &Arc<ClientContext>, address: &str) -> Result<()> {
    let cfg = &state.network.airegistry;
    let (a, p, s) = match (&cfg.giver_address, &cfg.giver_pubkey, &cfg.giver_secret) {
        (Some(a), Some(p), Some(s)) => (a, p, s),
        _ => bail!(
            "network '{}' has no Giver — fund the deploy address out-of-band before deploying",
            state.network.name
        ),
    };
    GiverClient::new(
        ctx.clone(),
        a,
        p,
        s,
        &state.network.send_endpoint,
        state.http.clone(),
    )
    .fund_deploy_address(address, DEPLOY_FUND_VMSHELL)
    .await
}

/// Deploy an airegistry contract signed by `signer`: derive (local), fund (Giver),
/// send, wait Active. Idempotent — reuses an already-Active address.
async fn deploy_signed(
    state: &AppState,
    ctx: &Arc<ClientContext>,
    abi: &str,
    tvc: &[u8],
    init_data: Value,
    ctor: Value,
    signer: &Signer,
) -> Result<(String, bool)> {
    let msg = build_deploy(
        ctx,
        abi,
        tvc,
        init_data,
        ctor,
        &signer.public,
        &signer.secret,
    )
    .await?;
    let cfg = &state.network.airegistry;
    let r = reader(state);
    if r.is_active(cfg, &msg.address, &AccountOrigin::SelfOriginating)
        .await?
    {
        return Ok((msg.address, true));
    }
    fund_via_giver(state, ctx, &msg.address).await?;
    wait_status(&r, cfg, &msg.address, "Uninit", 150).await?;
    let resp = wallet::query::send_message(
        &state.http,
        &state.network.send_endpoint,
        &msg.message_boc_b64,
    )
    .await?;
    // Surface a mapped revert immediately (§11) rather than waiting 150s for an
    // Active that will never come.
    check_send_response(&resp)?;
    wait_status(&r, cfg, &msg.address, "Active", 150).await?;
    Ok((msg.address, false))
}

/// A signer-ref-signed external call to an airegistry contract (creator ops:
/// consumeSession / replenish / setEndpoint / withdrawShell / destroy).
async fn signed_external(
    state: &AppState,
    ctx: &Arc<ClientContext>,
    abi: &str,
    addr: &str,
    method: &str,
    input: Value,
    signer: &Signer,
) -> Result<Value> {
    let boc = encode_external_call(
        ctx,
        abi,
        addr,
        method,
        input,
        &signer.public,
        &signer.secret,
    )
    .await?;
    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;
    check_send_response(&resp)?;
    Ok(resp)
}

/// Resolve a creator `signer_ref` arg.
async fn resolve_signer(state: &AppState, args: &Value) -> Result<Signer> {
    let sr = args
        .get("signer_ref")
        .ok_or_else(|| anyhow!("`signer_ref` is required"))?;
    SignerRef::parse(sr)?.resolve(state).await
}

/// Resolve an operational wallet's address: explicit arg, else the object-store
/// pointer written by `airegistry_deploy_buyer`.
async fn resolve_oper_address(state: &AppState, args: &Value) -> Result<String> {
    if let Some(a) = opt_str(args, "oper_wallet_address") {
        return Ok(a.to_string());
    }
    let id = req_str(args, "oper_wallet_id")?;
    let key = Store::new(state).oper_wallet_key(id);
    state
        .object_store()?
        .get(KIND_OPER_WALLET, &key)
        .await?
        .and_then(|b| b.get("address").and_then(|v| v.as_str()).map(String::from))
        .ok_or_else(|| anyhow!("operational wallet '{id}' not found — deploy it with airegistry_deploy_buyer or pass oper_wallet_address"))
}

/// Resolve a wallet's `(address, swarm_root?)` from its `wallet_id` via the
/// `deploy_wallet` metadata record (`ackinacki.wallet.metadata`) — or an
/// explicit address override. The `swarm_root` is needed because a
/// SwarmRoot-child wallet inherits the SwarmRoot's DApp id (it is NOT
/// self-originating), which getter reads against the wallet must address by.
async fn resolve_wallet(
    state: &AppState,
    wallet_id: &str,
    addr_override: Option<&str>,
) -> Result<(String, Option<String>)> {
    if let Some(a) = addr_override {
        return Ok((a.to_string(), None));
    }
    let oper_key = Store::new(state).oper_wallet_key(wallet_id);
    if let Some(b) = state
        .object_store()?
        .get(KIND_OPER_WALLET, &oper_key)
        .await?
    {
        if let Some(addr) = b.get("address").and_then(|v| v.as_str()) {
            return Ok((
                addr.to_string(),
                b.get("swarm_root")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            ));
        }
    }
    let meta = state
        .object_store()?
        .get(WALLET_METADATA_KIND, wallet_id)
        .await?;
    let addr = meta.as_ref().and_then(|b| b.get("address").and_then(|v| v.as_str()).map(String::from))
        .ok_or_else(|| anyhow!("wallet '{wallet_id}' address not found — deploy it (deploy_wallet/airegistry_deploy_buyer) or pass the address explicitly"))?;
    let swarm_root = meta.and_then(|b| {
        b.get("swarm_root")
            .and_then(|v| v.as_str())
            .map(String::from)
    });
    Ok((addr, swarm_root))
}

/// A queued multisig transaction: enough to attribute a transaction to the
/// exact submit that created it (the submitting custodian's pubkey +
/// destination + native value + attached SHELL).
struct QueuedTx {
    id: u64,
    dest: String,
    /// Native (gas-token) value attached to the transfer.
    value: u128,
    ecc2: u128,
    creator_pubkey: Option<String>,
}

fn norm_pubkey(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

/// Queued transactions on the wallet via `getTransactions`, addressed by
/// `origin`. Errors if the account isn't readable under `origin` — used as a
/// preflight (validates the read origin BEFORE an irreversible submit) and to
/// snapshot existing transactions so the genuinely-new one can be matched after.
async fn read_transactions(
    state: &AppState,
    wallet_addr: &str,
    origin: &AccountOrigin,
) -> Result<Vec<QueuedTx>> {
    let r = getter_read(
        state,
        MULTISIG_ABI_JSON,
        wallet_addr,
        "getTransactions",
        json!({}),
        origin,
    )
    .await
    .map_err(|e| anyhow!("getTransactions read on {wallet_addr} failed: {e}"))?;
    let mut out = Vec::new();
    for t in r
        .get("transactions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let id = t
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok());
        let dest = t.get("dest").and_then(|v| v.as_str()).map(String::from);
        let value = t
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let ecc2 = t
            .get("cc")
            .and_then(|cc| cc.get("2"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let creator_pubkey = t
            .pointer("/creator/owner_pubkey")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && norm_pubkey(s).chars().all(|c| c.is_ascii_hexdigit()))
            .map(norm_pubkey);
        if let (Some(id), Some(dest)) = (id, dest) {
            out.push(QueuedTx {
                id,
                dest,
                value,
                ecc2,
                creator_pubkey,
            });
        }
    }
    Ok(out)
}

/// Resolve a single queued multisig transaction by id, reading the wallet under
/// `dapp_id` (its SwarmRoot DApp id for a SwarmRoot-child wallet, or its own
/// address when self-originating). Returns the transaction's canonical
/// destination account id + the larger of its native value / attached ECC[2]
/// SHELL — the amount a spend policy should bound. `Ok(None)` if no such id is
/// queued. Errors (fail closed) if the wallet can't be read under `dapp_id`.
///
/// Used by `confirm_transaction` so the second custodian's release is gated by
/// the same destination/amount policy the first custodian's submit would face.
pub(crate) async fn read_queued_tx_for_policy(
    state: &AppState,
    wallet_addr: &str,
    dapp_id: Option<&str>,
    tx_id: u64,
) -> Result<Option<(String, u128)>> {
    use crate::airegistry::getter::bare_account_id;
    let origin = match dapp_id.filter(|s| !s.is_empty()) {
        Some(d) => {
            let id = bare_account_id(d).map_err(|e| anyhow!("invalid dapp_id: {e}"))?;
            AccountOrigin::Explicit { dapp_id: id }
        }
        None => AccountOrigin::SelfOriginating,
    };
    let txs = read_transactions(state, wallet_addr, &origin).await?;
    Ok(txs.into_iter().find(|t| t.id == tx_id).map(|t| {
        let dest = bare_account_id(&t.dest).unwrap_or_else(|_| t.dest.clone());
        (dest, t.value.max(t.ecc2))
    }))
}

/// The wallet's `requiredTxnConfirms` (from `getParameters`). Doubles as a
/// preflight that the account is readable + is a multisig under `origin`.
async fn treasury_required_confirms(
    state: &AppState,
    wallet_addr: &str,
    origin: &AccountOrigin,
) -> Result<u8> {
    let p = getter_read(
        state,
        MULTISIG_ABI_JSON,
        wallet_addr,
        "getParameters",
        json!({}),
        origin,
    )
    .await?;
    p.get("requiredTxnConfirms")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u8>().ok())
        .ok_or_else(|| {
            anyhow!("could not read requiredTxnConfirms from getParameters on {wallet_addr}")
        })
}

/// Decide how to address `getTransactionIds` on the treasury. The selected dapp
/// id is **syntactically** validated/normalised here via `bare_account_id` (the
/// same check the getter path applies). Whether it is the *correct* dapp id (the
/// treasury is actually readable under it) is proven by the caller's preflight
/// read BEFORE any submit — see `fund_buyer`.
///
/// Precedence: an explicit `treasury_dapp_id` arg, then the treasury's SwarmRoot
/// (from metadata, addressed as a SwarmChild), then self-originating. An explicit
/// `treasury_wallet_address` override with no way to determine the dapp id is
/// rejected.
fn treasury_tx_read_origin(
    args: &Value,
    swarm_root: Option<&str>,
    used_override: bool,
) -> Result<AccountOrigin> {
    use crate::airegistry::getter::bare_account_id;
    if let Some(d) = opt_str(args, "treasury_dapp_id") {
        let dapp_id = bare_account_id(d).map_err(|e| anyhow!("invalid treasury_dapp_id: {e}"))?;
        return Ok(AccountOrigin::Explicit { dapp_id });
    }
    if let Some(sr) = swarm_root.filter(|s| !s.is_empty()) {
        let dapp_id = bare_account_id(sr)
            .map_err(|e| anyhow!("treasury swarm_root is not a valid address: {e}"))?;
        return Ok(AccountOrigin::SwarmChild { dapp_id });
    }
    if used_override {
        bail!(
            "treasury_wallet_address override requires treasury_dapp_id (the treasury's DApp id — \
             its SwarmRoot address for a deploy_wallet treasury, or its own address if self-originating); \
             without it the queued transaction id can't be read for confirm_transaction"
        );
    }
    Ok(AccountOrigin::SelfOriginating)
}

/// A consumer wallet-internal forward (buy/confirm): the wallet `submitTransaction`s
/// an inner call (+ optional ECC[2] SHELL) to the token contract. Policy-gated.
#[allow(clippy::too_many_arguments)]
async fn wallet_forward_call(
    state: &AppState,
    ctx: &Arc<ClientContext>,
    wallet_addr: &str,
    wallet_id: &str,
    role: &str,
    token: &str,
    shell: u128,
    method: &str,
    input: Value,
) -> Result<Value> {
    validate_wallet_id(wallet_id)?;
    validate_signer_role(role)?;
    // Rate-limit by the CANONICAL account id (an explicit oper_wallet_address
    // override is returned unchanged, so alternate spellings would otherwise get
    // separate buckets and dodge the limiter). enforce_wallet_policy canonicalizes
    // its own lookup key internally.
    let wallet_key = crate::airegistry::getter::bare_account_id(wallet_addr)
        .unwrap_or_else(|_| wallet_addr.to_string());
    state.tx_rate_limiter.check(&wallet_key)?;
    enforce_wallet_policy(state, wallet_addr, token, shell).await?;
    let public = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, role)
        .await?
        .ok_or_else(|| anyhow!("{role} pubkey not found for wallet '{wallet_id}'"))?;
    let secret = get_wallet_key_value(state, WALLET_PRIVKEY_KIND, wallet_id, role)
        .await?
        .ok_or_else(|| anyhow!("{role} privkey not found for wallet '{wallet_id}'"))?;
    let payload =
        encode_internal_payload(ctx, Contract::TokenContract.abi_json(), method, input).await?;
    let boc = wallet_forward(
        ctx,
        MULTISIG_ABI_JSON,
        wallet_addr,
        token,
        AIREGISTRY_GAS_VMSHELL,
        shell,
        true,
        &payload,
        &public,
        &secret,
    )
    .await?;
    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;
    // A reverted submitTransaction (bad key, no balance, frozen wallet, …) must
    // surface as a mapped §11 error, not success-shaped JSON.
    check_send_response(&resp)?;
    Ok(resp)
}

// ----- dispatch ----------------------------------------------------------

pub async fn call_airegistry_tool(
    state: &AppState,
    name: &str,
    args: Value,
) -> Option<Result<Value>> {
    let r = match name {
        // generic
        "call_contract" => call_contract(state, args).await,
        "deploy_contract" => deploy_contract(state, args).await,
        // creator
        "airegistry_deploy_super_root" => deploy_super_root(state, args).await,
        "airegistry_register_model" => register_model(state, args).await,
        "airegistry_set_manifest" => set_manifest(state, args).await,
        "airegistry_get_manifest" => get_manifest(state, args).await,
        "airegistry_list_marketplace" => list_marketplace(state, args).await,
        "airegistry_create_token_lot" => create_token_lot(state, args).await,
        "airegistry_bill_session" => bill_session(state, args).await,
        "airegistry_replenish" => replenish(state, args).await,
        "airegistry_set_endpoint" => set_endpoint(state, args).await,
        "airegistry_withdraw_shell" => withdraw_shell(state, args).await,
        "airegistry_destroy_lot" => destroy_lot(state, args).await,
        "airegistry_get_lot" => get_lot(state, args).await,
        // consumer
        "airegistry_resolve_model" => resolve_model(state, args).await,
        "airegistry_deploy_buyer" => deploy_buyer(state, args).await,
        "airegistry_fund_buyer" => fund_buyer(state, args).await,
        "airegistry_buy_tokens" => buy_tokens(state, args).await,
        "airegistry_cancel" => cancel_reservation(state, args).await,
        "airegistry_get_entitlement" => get_entitlement(state, args).await,
        // stateless user-signed payments (Flow A)
        "airegistry_prepare_user_buy_tokens" => prepare_user_buy_tokens(state, args).await,
        "airegistry_prepare_user_cancel" => prepare_user_cancel(state, args).await,
        "airegistry_verify_payment_readiness" => verify_payment_readiness(state, args).await,
        _ => return None,
    };
    Some(r)
}

// ----- §9.1 generic ------------------------------------------------------

async fn call_contract(state: &AppState, args: Value) -> Result<Value> {
    let address = req_str(&args, "address")?;
    let method = req_str(&args, "method")?;
    let abi = resolve_abi(&args)?;
    let params = args.get("params").cloned().unwrap_or_else(|| json!({}));
    // signer_ref present ⇒ state-changing signed ext-in; absent ⇒ getter read.
    if args.get("signer_ref").is_some() {
        let ctx = local_context()?;
        let signer = resolve_signer(state, &args).await?;
        let resp = signed_external(state, &ctx, &abi, address, method, params, &signer).await?;
        Ok(json!({ "address": address, "method": method, "send_response": resp }))
    } else {
        let origin = origin_for(&args, &state.network.airegistry);
        let output = getter_read(state, &abi, address, method, params, &origin).await?;
        Ok(json!({ "address": address, "method": method, "output": output }))
    }
}

async fn deploy_contract(state: &AppState, args: Value) -> Result<Value> {
    let abi = resolve_abi(&args)?;
    let tvc = resolve_tvc(&args)?;
    let init_data = args
        .get("var_init")
        .or_else(|| args.get("init_data"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let ctor = args
        .get("constructor_params")
        .or_else(|| args.get("ctor"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let (address, reused) =
        deploy_signed(state, &ctx, &abi, &tvc, init_data, ctor, &signer).await?;
    Ok(json!({ "address": address, "status": if reused { "already_active" } else { "deployed" } }))
}

// ----- §9.2 creator ------------------------------------------------------

async fn deploy_super_root(state: &AppState, args: Value) -> Result<Value> {
    let pubkey = req_str(&args, "pubkey")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let ctor = json!({
        "pubkey": hexparam(pubkey),
        "rootModelCode": Contract::RootModel.code_boc_b64()?,
        "manifestCode": Contract::ManifestMetadata.code_boc_b64()?,
    });
    let (address, reused) = deploy_signed(
        state,
        &ctx,
        Contract::SuperRoot.abi_json(),
        Contract::SuperRoot.tvc(),
        json!({}),
        ctor,
        &signer,
    )
    .await?;
    let persist = Store::new(state).put_super_root(pubkey, &address).await;
    Ok(fold_persist(
        json!({ "super_root_address": address, "status": if reused { "already_active" } else { "deployed" } }),
        persist,
    ))
}

async fn register_model(state: &AppState, args: Value) -> Result<Value> {
    let super_root = req_str(&args, "super_root_address")?;
    let owner_pubkey = req_str(&args, "owner_pubkey")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let init = json!({ "_ownerPubkey": hexparam(owner_pubkey), "_superRootAddress": super_root });
    let ctor = json!({ "tokenContractCode": Contract::TokenContract.code_boc_b64()? });
    let (address, reused) = deploy_signed(
        state,
        &ctx,
        Contract::RootModel.abi_json(),
        Contract::RootModel.tvc(),
        init,
        ctor,
        &signer,
    )
    .await?;
    let persist = Store::new(state)
        .put_root_model(super_root, owner_pubkey, &address)
        .await;
    Ok(fold_persist(
        json!({ "root_model_address": address, "status": if reused { "already_active" } else { "deployed" } }),
        persist,
    ))
}

/// Max package bytes per chunk — under the ~64KB single-message limit, leaving
/// headroom for the ABI header + signature. The package is stored as indexed
/// chunks (`setApiSchemaChunk(idx, chunk)`), each an O(1) write regardless of how
/// many already exist, so there's no practical cap on total package size.
const MANIFEST_CHUNK_BYTES: usize = 32 * 1024;

/// Split `s` into `<= max_bytes` pieces on UTF-8 char boundaries, so
/// concatenating the pieces on-chain reproduces `s` byte-for-byte.
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

/// Read one manifest chunk (`getApiSchemaChunk(idx)`).
async fn mf_read_chunk(
    state: &AppState,
    abi: &str,
    addr: &str,
    idx: u32,
    origin: &AccountOrigin,
) -> Result<String> {
    let r = getter_read(
        state,
        abi,
        addr,
        "getApiSchemaChunk",
        json!({ "idx": idx }),
        origin,
    )
    .await?;
    Ok(r.get("value0")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
}

/// Number of chunk indices ever written (`getApiSchemaChunkCount`, = max idx + 1).
async fn mf_chunk_count(
    state: &AppState,
    abi: &str,
    addr: &str,
    origin: &AccountOrigin,
) -> Result<u32> {
    let r = getter_read(
        state,
        abi,
        addr,
        "getApiSchemaChunkCount",
        json!({}),
        origin,
    )
    .await?;
    r.get("value0")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("could not read getApiSchemaChunkCount on {addr}"))
}

/// Apply one chunk write/delete and CONFIRM it landed on-chain — the chunk at
/// `idx` must read back as EXACTLY `expected` (the chunk content, or `""` for a
/// delete). Comparing content, not just length, is required: on a reused manifest
/// a pre-update chunk of the same length would otherwise false-confirm before the
/// write actually applied. `send_message` only proves the BOC was posted, not
/// that the account state updated, and rapid external sends can drop;
/// `setApiSchemaChunk` / `deleteApiSchemaChunk` are idempotent, so we retry.
#[allow(clippy::too_many_arguments)]
async fn mf_apply_chunk(
    state: &AppState,
    ctx: &Arc<ClientContext>,
    abi: &str,
    addr: &str,
    idx: u32,
    method: &str,
    params: Value,
    expected: &str,
    signer: &Signer,
) -> Result<()> {
    for _ in 0..4 {
        signed_external(state, ctx, abi, addr, method, params.clone(), signer).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            // A read error must NOT confirm (especially for a delete, where the
            // expected value is the empty string).
            if let Ok(got) =
                mf_read_chunk(state, abi, addr, idx, &AccountOrigin::SelfOriginating).await
            {
                if got == expected {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
    bail!("manifest chunk {idx} ({method}) did not land on-chain after retries")
}

/// Creator: store the **full canonical package** ON-CHAIN in `ManifestMetadata`
/// as indexed chunks. The package is the authoritative, blockchain-only source of
/// truth — no off-chain package store, no gosh.memory dependency. The package is
/// split into ≤32KB chunks written at indices `0..n` via `setApiSchemaChunk`
/// (each an O(1) write — no growing-string gas cap, so any size fits). Every
/// write is confirmed on-chain (with idempotent retry), the stale tail of a
/// smaller re-set is deleted, and a final reassembly + sha256 check proves the
/// package actually persisted before success is reported.
async fn set_manifest(state: &AppState, args: Value) -> Result<Value> {
    let super_root = req_str(&args, "super_root_address")?;
    let root_model = req_str(&args, "root_model_address")?;
    let owner_pubkey = req_str(&args, "owner_pubkey")?;
    // The full package content; `api_schema_json` kept as an alias for the arg.
    let package = opt_str(&args, "package")
        .or_else(|| opt_str(&args, "api_schema_json"))
        .ok_or_else(|| {
            anyhow!("`package` is required — the full canonical package stored on-chain")
        })?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let chunks = chunk_str(package, MANIFEST_CHUNK_BYTES);
    let abi = Contract::ManifestMetadata.abi_json();
    let so = AccountOrigin::SelfOriginating;
    let init = json!({ "_ownerPubkey": hexparam(owner_pubkey), "_rootModelAddress": root_model, "_superRootAddress": super_root });
    let (address, reused) = deploy_signed(
        state,
        &ctx,
        abi,
        Contract::ManifestMetadata.tvc(),
        init,
        json!({ "firstChunk": chunks[0] }),
        &signer,
    )
    .await?;
    // On reuse the prior package may have had more chunks — read the count so the
    // stale tail can be cleared. Fail closed if it's unreadable (don't silently
    // skip the cleanup, which would leave stale chunks corrupting the read).
    let old_count: u32 = if reused {
        mf_chunk_count(state, abi, &address, &so)
            .await
            .map_err(|e| anyhow!("could not read existing manifest chunk count (needed to clear stale chunks before overwrite): {e}"))?
    } else {
        0
    };
    // Write every chunk index (0..n), confirming each landed (idempotent retry).
    for (i, c) in chunks.iter().enumerate() {
        mf_apply_chunk(
            state,
            &ctx,
            abi,
            &address,
            i as u32,
            "setApiSchemaChunk",
            json!({ "idx": i, "chunk": c }),
            c,
            &signer,
        )
        .await?;
    }
    // Clear the stale tail of a previous, larger package.
    for idx in (chunks.len() as u32)..old_count {
        mf_apply_chunk(
            state,
            &ctx,
            abi,
            &address,
            idx,
            "deleteApiSchemaChunk",
            json!({ "idx": idx }),
            "",
            &signer,
        )
        .await?;
    }
    // Authoritative readback: reassemble the on-chain chunks and verify the hash
    // BEFORE reporting success — never claim a package persisted that didn't.
    let count = mf_chunk_count(state, abi, &address, &so).await?;
    let mut on_chain = String::new();
    for idx in 0..count {
        on_chain.push_str(&mf_read_chunk(state, abi, &address, idx, &so).await?);
    }
    let want = sha256_hex(package.as_bytes());
    if sha256_hex(on_chain.as_bytes()) != want {
        bail!(
            "manifest readback mismatch on {address}: on-chain package ({} bytes) sha256 != intended ({} bytes) — chunks dropped or stale; the package did NOT fully persist",
            on_chain.len(),
            package.len()
        );
    }
    let persist = Store::new(state)
        .put_manifest(super_root, root_model, owner_pubkey, &address)
        .await;
    Ok(fold_persist(
        json!({
            "manifest_address": address,
            "updated": reused,
            "bytes": package.len(),
            "chunks": chunks.len(),
            "sha256": want,
            "verified": true,
        }),
        persist,
    ))
}

/// Read the full canonical package straight from chain. Reads
/// `getApiSchemaChunkCount` then each `getApiSchemaChunk(idx)` and concatenates
/// them in order. Resolves the manifest address from an explicit arg or via
/// `SuperRoot.getManifestAddress`. No memory dependency. When `expected_sha256`
/// is given, the reassembled package is integrity-checked against it.
async fn get_manifest(state: &AppState, args: Value) -> Result<Value> {
    let origin = origin_for(&args, &state.network.airegistry);
    let manifest = if let Some(a) = opt_str(&args, "manifest_address") {
        a.to_string()
    } else {
        let super_root = req_str(&args, "super_root_address")?;
        let owner = req_str(&args, "owner_pubkey")?;
        let root_model = req_str(&args, "root_model_address")?;
        let r = getter_read(
            state,
            Contract::SuperRoot.abi_json(),
            super_root,
            "getManifestAddress",
            json!({ "ownerPubkey": hexparam(owner), "rootModelAddress": root_model }),
            &origin,
        )
        .await?;
        r.get("value0")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let abi = Contract::ManifestMetadata.abi_json();
    let count = mf_chunk_count(state, abi, &manifest, &origin).await?;
    let mut package = String::new();
    for idx in 0..count {
        package.push_str(&mf_read_chunk(state, abi, &manifest, idx, &origin).await?);
    }
    let sha256 = sha256_hex(package.as_bytes());
    let mut out = json!({ "manifest_address": manifest, "package": package, "bytes": package.len(), "chunks": count, "sha256": sha256 });
    if let Some(expected) = opt_str(&args, "expected_sha256") {
        out["sha256_ok"] =
            json!(sha256.eq_ignore_ascii_case(expected.trim().trim_start_matches("0x")));
    }
    Ok(out)
}

/// Lowercase hex sha256 — the package content hash used as the on-chain
/// integrity anchor.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Order-preserving dedup of addresses by their canonical bare account id.
fn dedup_addrs(addrs: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for a in addrs {
        if seen.insert(a.trim_start_matches("0:").to_lowercase()) {
            out.push(a);
        }
    }
    out
}

/// Map a registration event to `(kind, address)`, or `None` if it isn't one.
fn registration_of(e: &AiRegistryEvent) -> Option<(&'static str, &str)> {
    match e {
        AiRegistryEvent::RootRegistered { root } => Some(("RootRegistered", root)),
        AiRegistryEvent::ManifestRegistered { manifest } => Some(("ManifestRegistered", manifest)),
        AiRegistryEvent::TokenContractRegistered { token } => {
            Some(("TokenContractRegistered", token))
        }
        _ => None,
    }
}

/// Resolve the SuperRoot to read for marketplace discovery: an explicit
/// `super_root_address` arg wins, else the network's configured default
/// (`airegistry.super_root_address`, set via `--airegistry-super-root` /
/// `GOSH_AIREGISTRY_SUPER_ROOT`). Errors clearly if neither exists — so a client
/// (e.g. a backend indexer) need not know the deployment's SuperRoot, while a
/// service with no default still fails loudly rather than silently.
fn resolve_super_root(args: &Value, cfg: &AiRegistryConfig) -> Result<String> {
    if let Some(s) = opt_str(args, "super_root_address") {
        return Ok(s.to_string());
    }
    if let Some(s) = cfg.super_root_address.as_deref().filter(|s| !s.is_empty()) {
        return Ok(s.to_string());
    }
    bail!(
        "no SuperRoot to list: pass `super_root_address`, or configure a network \
         default for this service (--airegistry-super-root / GOSH_AIREGISTRY_SUPER_ROOT)"
    )
}

/// Discovery by EVENTS (blockchain-native, no Memory): enumerate the marketplace
/// from the on-chain registration **event log** — the log IS the catalog. With a
/// `super_root_address` (explicit arg or the configured network default), reads
/// its `RootRegistered` (models) + `ManifestRegistered` (packages); with a
/// `root_model_address`, its `TokenContractRegistered` (lots).
///
/// This is a real **sync contract**, not just a recent-window peek: events are
/// returned oldest-first with stable identity (`message_id`, `lt`) and a per-event
/// `cursor`, plus a `page_info { has_more, end_cursor, scanned }`. A backend
/// indexer pages forward with `first` + `after` (the prior `end_cursor`),
/// persists `end_cursor` as a checkpoint, and knows it has caught up when
/// `has_more` is false. The deduped `root_models`/`manifests`/`token_lots` are a
/// convenience view of THIS page. Read-only-safe (no getter-over-BOC, no Memory).
async fn list_marketplace(state: &AppState, args: Value) -> Result<Value> {
    let cfg = &state.network.airegistry;
    let origin = origin_for(&args, cfg);
    let rdr = reader(state);
    // `first` is the page size (alias `last` for compatibility), capped at 200.
    let first = args
        .get("first")
        .or_else(|| args.get("last"))
        .and_then(|v| v.as_u64())
        .unwrap_or(50)
        .clamp(1, 200) as u32;
    let after = opt_str(&args, "after");

    let (addr, abi, is_model) = if let Some(rm) = opt_str(&args, "root_model_address") {
        (rm.to_string(), Contract::RootModel.abi_json(), true)
    } else {
        (
            resolve_super_root(&args, cfg)?,
            Contract::SuperRoot.abi_json(),
            false,
        )
    };

    let page = rdr
        .read_events(cfg, &addr, abi, &origin, first, after)
        .await?;

    // Ordered per-event records with on-chain identity — the canonical stream.
    let events: Vec<Value> = page
        .records
        .iter()
        .filter_map(|r| {
            registration_of(&r.event).map(|(kind, address)| {
                json!({
                    "kind": kind,
                    "address": address,
                    "message_id": r.message_id,
                    "lt": r.created_lt,
                    "created_at": r.created_at,
                    "cursor": r.cursor,
                })
            })
        })
        .collect();

    let mut out = json!({
        "events": events,
        "page_info": {
            "has_more": page.has_more,
            "end_cursor": page.end_cursor,
            "scanned_messages": page.scanned,
        },
        "source": "events",
    });

    // Convenience aggregation of THIS page (deduped addresses).
    if is_model {
        let lots = dedup_addrs(page.records.iter().filter_map(|r| match &r.event {
            AiRegistryEvent::TokenContractRegistered { token } => Some(token.clone()),
            _ => None,
        }));
        out["root_model_address"] = json!(addr);
        out["token_lots"] = json!(lots);
    } else {
        let models = dedup_addrs(page.records.iter().filter_map(|r| match &r.event {
            AiRegistryEvent::RootRegistered { root } => Some(root.clone()),
            _ => None,
        }));
        let manifests = dedup_addrs(page.records.iter().filter_map(|r| match &r.event {
            AiRegistryEvent::ManifestRegistered { manifest } => Some(manifest.clone()),
            _ => None,
        }));
        out["super_root_address"] = json!(addr);
        out["root_models"] = json!(models);
        out["manifests"] = json!(manifests);
    }
    Ok(out)
}

async fn create_token_lot(state: &AppState, args: Value) -> Result<Value> {
    let super_root = opt_str(&args, "super_root_address")
        .unwrap_or("")
        .to_string();
    let root_model = req_str(&args, "root_model_address")?;
    let seller_pubkey = req_str(&args, "seller_pubkey")?;
    // Checked ABI-range conversions — reject out-of-range input instead of
    // silently truncating to a different on-chain address/config.
    let nonce = req_u64(&args, "nonce")?;
    let model_name = req_str(&args, "model_name")?;
    let endpoint = req_str(&args, "endpoint")?;
    let total = req_u128(&args, "total_tokens_for_sale")?;
    let tick = req_u128(&args, "tick_size")?;
    let burn_fee_bps = req_u16(&args, "burn_fee_bps")?;
    let max_sessions = req_u8(&args, "max_reserved_sessions")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let init = json!({ "_sellerPubkey": hexparam(seller_pubkey), "_rootModelAddress": root_model, "_nonce": nonce.to_string() });
    let ctor = json!({
        "modelName": model_name, "endpoint": endpoint,
        "totalTokensForSale": total.to_string(), "tickSize": tick.to_string(),
        "burnFeeBps": burn_fee_bps, "maxReservedSessions": max_sessions,
    });
    let (address, reused) = deploy_signed(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        Contract::TokenContract.tvc(),
        init,
        ctor,
        &signer,
    )
    .await?;
    // The package itself lives on-chain in ManifestMetadata (set via
    // airegistry_set_manifest). The TokenContract lot has NO on-chain package
    // hash; `package_sha256` is persisted only as off-chain pointer metadata in
    // the Memory object-store below, so a buyer must verify integrity by reading
    // ManifestMetadata via airegistry_get_manifest — never trust the off-chain
    // pointer as a chain fact.
    let persist = Store::new(state)
        .put_token_lot(
            &super_root,
            root_model,
            seller_pubkey,
            nonce,
            &address,
            model_name,
            endpoint,
            opt_str(&args, "package_sha256"),
        )
        .await;
    Ok(fold_persist(
        json!({ "token_contract_address": address, "status": if reused { "already_active" } else { "deployed" } }),
        persist,
    ))
}

async fn bill_session(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let sessions = req_u16(&args, "sessions")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let resp = signed_external(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        token,
        "consumeSession",
        json!({ "sessions": sessions }),
        &signer,
    )
    .await?;
    Ok(json!({ "token_contract_address": token, "sessions": sessions, "send_response": resp }))
}

async fn replenish(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let amount = req_u128(&args, "amount")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let resp = signed_external(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        token,
        "replenishTokensForSale",
        json!({ "amount": amount.to_string() }),
        &signer,
    )
    .await?;
    Ok(
        json!({ "token_contract_address": token, "amount": amount.to_string(), "send_response": resp }),
    )
}

async fn set_endpoint(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let endpoint = req_str(&args, "endpoint")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let resp = signed_external(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        token,
        "setEndpoint",
        json!({ "newEndpoint": endpoint }),
        &signer,
    )
    .await?;
    Ok(json!({ "token_contract_address": token, "endpoint": endpoint, "send_response": resp }))
}

async fn withdraw_shell(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let amount = req_u128(&args, "amount")?;
    let recipient = req_str(&args, "recipient")?;
    if amount == 0 {
        bail!("amount must be > 0");
    }
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let resp = signed_external(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        token,
        "withdrawShell",
        json!({ "amount": amount.to_string(), "recipient": recipient }),
        &signer,
    )
    .await?;
    Ok(
        json!({ "token_contract_address": token, "amount": amount.to_string(), "recipient": recipient, "send_response": resp }),
    )
}

async fn destroy_lot(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let payout = req_str(&args, "payout_address")?;
    let ctx = local_context()?;
    let signer = resolve_signer(state, &args).await?;
    let resp = signed_external(
        state,
        &ctx,
        Contract::TokenContract.abi_json(),
        token,
        "destroy",
        json!({ "payoutAddress": payout }),
        &signer,
    )
    .await?;
    Ok(json!({ "token_contract_address": token, "payout_address": payout, "send_response": resp }))
}

async fn get_lot(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let origin = origin_for(&args, &state.network.airegistry);
    let abi = Contract::TokenContract.abi_json();
    let counters = getter_read(state, abi, token, "getCounters", json!({}), &origin).await?;
    let config = getter_read(state, abi, token, "getConfig", json!({}), &origin).await?;
    let buyer = getter_read(state, abi, token, "getCurrentBuyer", json!({}), &origin).await?;
    let shell = getter_read(state, abi, token, "getShellBalance", json!({}), &origin).await?;
    Ok(json!({
        "token_contract_address": token,
        "counters": counters, "config": config,
        "current_buyer": buyer.get("value0"), "shell_balance": shell.get("value0"),
    }))
}

// ----- §9.3 consumer -----------------------------------------------------

async fn resolve_model(state: &AppState, args: Value) -> Result<Value> {
    let super_root = req_str(&args, "super_root_address")?;
    let owner_pubkey = req_str(&args, "owner_pubkey")?;
    let seller_pubkey = req_str(&args, "seller_pubkey")?;
    let nonce = req_u64(&args, "nonce")?;
    let origin = origin_for(&args, &state.network.airegistry);
    let rm = getter_read(
        state,
        Contract::SuperRoot.abi_json(),
        super_root,
        "getRootModelAddress",
        json!({ "ownerPubkey": hexparam(owner_pubkey) }),
        &origin,
    )
    .await?;
    let root_model = rm
        .get("value0")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let tc = getter_read(
        state,
        Contract::RootModel.abi_json(),
        &root_model,
        "getTokenContractAddress",
        json!({ "sellerPubkey": hexparam(seller_pubkey), "nonce": nonce.to_string() }),
        &origin,
    )
    .await?;
    let token_contract = tc
        .get("value0")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let endpoint = getter_read(
        state,
        Contract::TokenContract.abi_json(),
        &token_contract,
        "getEndpoint",
        json!({}),
        &origin,
    )
    .await
    .ok()
    .and_then(|v| v.get("value0").and_then(|x| x.as_str()).map(String::from));
    Ok(
        json!({ "root_model_address": root_model, "token_contract_address": token_contract, "endpoint": endpoint }),
    )
}

async fn deploy_buyer(state: &AppState, args: Value) -> Result<Value> {
    let oper_wallet_id = req_str(&args, "oper_wallet_id")?;
    let swarm_root = req_str(&args, "swarm_root_address")?;
    validate_wallet_id(oper_wallet_id)?;
    // create_keys ×3 (idempotent — skip roles that already exist), then deploy
    // the 3-custodian wallet with reqConfirms=1 (autonomous 1-sig spends).
    for role in ["agent", "controller", "owner"] {
        let exists = get_wallet_key_value(state, WALLET_PUBKEY_KIND, oper_wallet_id, role)
            .await?
            .is_some();
        if !exists {
            super::tools::create_keys(state, json!({ "role": role, "wallet_id": oper_wallet_id }))
                .await?;
        }
    }
    let deployed = super::tools::deploy_wallet(
        state,
        json!({
            "wallet_id": oper_wallet_id,
            "swarm_root_address": swarm_root,
            "req_confirms": 1,
        }),
    )
    .await?;
    let address = deployed
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // The oper_wallet pointer is relied on by later buy/confirm calls, so a
    // persist failure is surfaced (persisted:false) rather than silently
    // dropped — the caller still gets the address and can pass it explicitly.
    let persist = Store::new(state)
        .put_oper_wallet(oper_wallet_id, &address)
        .await;
    Ok(fold_persist(
        json!({ "oper_wallet_address": address, "oper_wallet_id": oper_wallet_id }),
        persist,
    ))
}

async fn fund_buyer(state: &AppState, args: Value) -> Result<Value> {
    let treasury_wallet_id = req_str(&args, "treasury_wallet_id")?;
    let signer_role = req_str(&args, "signer_role")?;
    let oper_address = req_str(&args, "oper_wallet_address")?;
    let shell_budget = req_u128(&args, "shell_budget")?;
    validate_wallet_id(treasury_wallet_id)?;
    validate_signer_role(signer_role)?;
    // Canonicalise the operational address BEFORE any irreversible submit: a
    // malformed/alternate textual form (e.g. uppercase hex) is rejected up-front,
    // and the queued-tx matcher compares canonical account ids — not raw,
    // case-sensitive strings that could miss the on-chain (lowercased) dest and
    // strand the queue.
    let oper_canon = crate::airegistry::getter::bare_account_id(oper_address)
        .map_err(|e| anyhow!("invalid oper_wallet_address: {e}"))?;
    // Resolve the treasury's address + swarm_root (DApp id) from its wallet
    // metadata (deploy_wallet) or an explicit override. The swarm_root is needed
    // to address the getTransactionIds read against a SwarmRoot-child treasury.
    let override_addr = opt_str(&args, "treasury_wallet_address");
    let (treasury_addr, treasury_swarm_root) =
        resolve_wallet(state, treasury_wallet_id, override_addr).await?;
    // Serialize the whole preflight → submit → poll window per treasury (keyed by
    // the CANONICAL account id, so alternate textual forms of the same treasury
    // share one lock), so two in-process top-ups can't race the tx correlation.
    let treasury_key = crate::airegistry::getter::bare_account_id(&treasury_addr)
        .unwrap_or_else(|_| treasury_addr.clone());
    let treasury_lock = {
        let mut map = state.fund_buyer_locks.lock();
        map.entry(treasury_key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _treasury_guard = treasury_lock.lock().await;
    // Decide how to read getTransactionIds BEFORE submitting — an unresolvable
    // dapp id (e.g. a treasury_wallet_address override with no treasury_dapp_id)
    // must be rejected up-front, never after the irreversible on-chain queue
    // (which a retry could then duplicate).
    let tx_origin = treasury_tx_read_origin(
        &args,
        treasury_swarm_root.as_deref(),
        override_addr.is_some(),
    )?;
    // Rate-limit + policy keyed/checked by canonical account ids (treasury key,
    // operational dest) so alternate spellings can't dodge either.
    state.tx_rate_limiter.check(&treasury_key)?;
    enforce_wallet_policy(state, &treasury_key, &oper_canon, shell_budget).await?;
    // PREFLIGHT (before any irreversible submit):
    // (1) the treasury must be GOVERNED — requiredTxnConfirms >= 2 — else
    //     submitTransaction executes the transfer immediately on the first
    //     signature (no second confirmation), silently bypassing the 2-of-3
    //     governance this tool promises. This read also proves the dapp id is
    //     actually correct (a valid-looking-but-wrong id fails here, no on-chain
    //     effect).
    let req_confirms = treasury_required_confirms(state, &treasury_addr, &tx_origin).await.map_err(|e| {
        anyhow!("treasury {treasury_addr} not readable as a multisig under the selected DApp id — rejecting before submit (wrong treasury_dapp_id?): {e}")
    })?;
    if req_confirms < 2 {
        bail!(
            "treasury {treasury_addr} is not governed: requiredTxnConfirms={req_confirms} (expected >= 2). \
             A 1-sig wallet would execute the top-up immediately on submit, without the second confirmation — \
             airegistry_fund_buyer only governs a 2-of-N treasury."
        );
    }
    // (2) snapshot the existing queued transactions so the genuinely-new one can
    //     be matched after the submit.
    let before = read_transactions(state, &treasury_addr, &tx_origin).await?;
    let before_ids: Vec<u64> = before.iter().map(|t| t.id).collect();
    let secret = get_wallet_key_value(state, WALLET_PRIVKEY_KIND, treasury_wallet_id, signer_role)
        .await?
        .ok_or_else(|| {
            anyhow!("{signer_role} privkey not found for treasury '{treasury_wallet_id}'")
        })?;
    // The custodian pubkey that signs this submit — the queued tx's creator, so
    // the new tx can be attributed to THIS submit (not a concurrent one from
    // another custodian).
    let my_pubkey = crate::airegistry::signer::derive_public(&secret)?;
    // GOVERNED top-up: a 2-of-N treasury submitTransaction QUEUES; a 2nd
    // custodian must confirm_transaction to release the budget.
    let addr_int = parse_address(&treasury_addr)?;
    let mut cc = BTreeMap::new();
    cc.insert(2u32, shell_budget);
    let boc = wallet::transact::encode_submit_transaction_full(
        &addr_int,
        oper_address,
        AIREGISTRY_GAS_VMSHELL,
        &cc,
        false,
        1,
        "",
        &secret,
    )?;
    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;
    // A rejected treasury submit must surface as a mapped §11 error, not a
    // success-shaped budget response.
    check_send_response(&resp)?;
    // Identify OUR new queued tx: present after-but-not-before AND attributable
    // to THIS submit — matching custodian creator pubkey + destination + ECC[2]
    // amount. The per-treasury lock removes in-process races; the creator match
    // rejects a concurrent submit by a different custodian; and if more than one
    // candidate still matches we refuse to guess (rather than ask the second
    // custodian to confirm the wrong top-up). The operational budget is NOT
    // recorded here (it would overstate budget before the second confirmation
    // settles).
    let deadline = Instant::now() + Duration::from_secs(45);
    let transaction_id = loop {
        let after = read_transactions(state, &treasury_addr, &tx_origin).await?;
        let matches: Vec<u64> = after
            .iter()
            .filter(|t| {
                !before_ids.contains(&t.id)
                    && crate::airegistry::getter::bare_account_id(&t.dest)
                        .ok()
                        .as_deref()
                        == Some(oper_canon.as_str())
                    && t.ecc2 == shell_budget
                    && t.creator_pubkey.as_deref() == Some(my_pubkey.as_str())
            })
            .map(|t| t.id)
            .collect();
        match matches.len() {
            1 => break matches[0],
            0 => {}
            n => bail!(
                "ambiguous: {n} new queued transactions on treasury {treasury_addr} match this submit \
                 (creator + dest + amount) — refusing to guess the transaction id; inspect getTransactions"
            ),
        }
        if Instant::now() > deadline {
            bail!("treasury {treasury_addr} submit accepted but no matching new queued transaction appeared");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    Ok(json!({
        "treasury_address": treasury_addr,
        "oper_wallet_address": oper_address,
        "shell_budget": shell_budget.to_string(),
        "queued": true,
        "transaction_id": transaction_id.to_string(),
        "required_confirms": req_confirms,
        "confirmations_remaining": req_confirms.saturating_sub(1),
        "note": format!(
            "governed top-up queued by 1 custodian; {} more custodian confirmation(s) (confirm_transaction(transaction_id)) release the budget",
            req_confirms.saturating_sub(1)
        ),
        "submit_response": resp,
    }))
}

async fn buy_tokens(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let shell = req_u128(&args, "shell_amount")?;
    if shell == 0 {
        bail!("shell_amount must be > 0");
    }
    let wallet_id = req_str(&args, "oper_wallet_id")?;
    let role = req_str(&args, "signer_role")?;
    let wallet_addr = resolve_oper_address(state, &args).await?;
    let ctx = local_context()?;
    let resp = wallet_forward_call(
        state,
        &ctx,
        &wallet_addr,
        wallet_id,
        role,
        token,
        shell,
        "buyTokens",
        json!({}),
    )
    .await?;
    Ok(
        json!({ "oper_wallet_address": wallet_addr, "token_contract_address": token, "shell_amount": shell.to_string(), "policy_checked": true, "send_response": resp }),
    )
}

/// Buyer-only stop-loss in the no-confirm flow: `cancel(payoutAddress)` refunds
/// the unconsumed `reservedTokens` (ECC[2] SHELL) and releases the lot lock.
/// `sellerOwed` (already-billed sessions) is left for the seller to withdraw.
///
/// The unconsumed **delegated budget is always refunded to the operational
/// wallet itself** — never a caller-supplied payout. The shared policy gate only
/// sees `(dest = token_contract, value = 0)`, so honouring an arbitrary payout
/// would let one custodian redirect the unconsumed budget to a blocked / non-
/// allowlisted address; refunding to the wallet keeps the budget inside the
/// governed boundary (the treasury reclaims it through normal governance).
async fn cancel_reservation(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let wallet_id = req_str(&args, "oper_wallet_id")?;
    let role = req_str(&args, "signer_role")?;
    let wallet_addr = resolve_oper_address(state, &args).await?;
    let ctx = local_context()?;
    let resp = wallet_forward_call(
        state,
        &ctx,
        &wallet_addr,
        wallet_id,
        role,
        token,
        0,
        "cancel",
        json!({ "payoutAddress": wallet_addr }),
    )
    .await?;
    Ok(
        json!({ "oper_wallet_address": wallet_addr, "token_contract_address": token, "payout_address": wallet_addr, "send_response": resp }),
    )
}

async fn get_entitlement(state: &AppState, args: Value) -> Result<Value> {
    let token = req_str(&args, "token_contract_address")?;
    let oper = req_str(&args, "oper_wallet_address")?;
    let origin = origin_for(&args, &state.network.airegistry);
    let abi = Contract::TokenContract.abi_json();
    let counters = getter_read(state, abi, token, "getCounters", json!({}), &origin).await?;
    let buyer = getter_read(state, abi, token, "getCurrentBuyer", json!({}), &origin).await?;
    let endpoint = getter_read(state, abi, token, "getEndpoint", json!({}), &origin)
        .await
        .ok()
        .and_then(|v| v.get("value0").and_then(|x| x.as_str()).map(String::from));
    let current_buyer = buyer
        .get("value0")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let is_this_buyer = current_buyer.trim_start_matches("0:") == oper.trim_start_matches("0:");
    Ok(json!({
        "token_contract_address": token,
        "oper_wallet_address": oper,
        "current_buyer": current_buyer,
        "is_current_buyer": is_this_buyer,
        // Tokens still reserved (refundable via cancel) vs sessions already
        // billed by the seller (consumeCalls) and the shell now owed to them.
        "reserved": counters.get("reservedTokens"),
        "consume_calls": counters.get("consumeCalls"),
        "seller_owed": counters.get("sellerOwed"),
        "endpoint": endpoint,
    }))
}

// ----- §9.4 stateless user-signed payments (Flow A) ----------------------
//
// These tools PREPARE a payment payload the user's OWN wallet wraps, signs, and
// submits. gosh-ackinacki only encodes the inner TokenContract payload
// (`encode_internal_payload`, wallet-ABI-agnostic) and reads chain state — it
// never accepts, resolves, or stores private keys, and runs with no gosh.memory.

/// SHELL is Acki Nacki extra-currency (ECC) id 2.
const SHELL_CURRENCY_ID: u64 = 2;

/// Parse a JSON string/number field to `u128`.
fn val_u128(v: Option<&Value>) -> Option<u128> {
    match v {
        Some(Value::String(s)) => s.parse().ok(),
        Some(Value::Number(n)) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// Optional `u128` arg (string or number).
fn opt_u128(args: &Value, key: &str) -> Option<u128> {
    val_u128(args.get(key))
}

/// Hard guard for the stateless payment tools: never accept key material. The
/// user's wallet signs; this service must never receive a key or signer.
fn reject_key_material(args: &Value) -> Result<()> {
    if let Some(obj) = args.as_object() {
        for k in obj.keys() {
            let kl = k.to_lowercase();
            if kl.contains("secret")
                || kl.contains("private")
                || kl.contains("privkey")
                || kl.contains("seed")
                || kl.contains("mnemonic")
                || kl == "signer"
                || kl == "signer_ref"
            {
                bail!(
                    "stateless payment tools never accept key material (offending arg `{k}`); \
                     the user's own wallet signs"
                );
            }
        }
    }
    Ok(())
}

/// Forward an optional `dapp_id` to a composed sub-read.
fn with_dapp_id(token: &str, oper: Option<&str>, args: &Value) -> Value {
    let mut v = json!({ "token_contract_address": token });
    if let Some(o) = oper {
        v["oper_wallet_address"] = json!(o);
    }
    if let Some(d) = opt_str(args, "dapp_id") {
        v["dapp_id"] = json!(d);
    }
    v
}

/// Prepare a frontend-safe **buyTokens** payment intent (Flow A) the user's own
/// wallet wraps + signs + submits. Encodes only the inner payload; `wallet_action`
/// states exactly what the wallet must do (attach ECC[2] SHELL + native vmshell
/// gas with the body). `buyTokens()` takes NO args — the amount is the attached
/// value, not a payload field — so the payload is method-only. `human_summary`
/// is derived from the same canonical inputs. Includes a chain preflight.
async fn prepare_user_buy_tokens(state: &AppState, args: Value) -> Result<Value> {
    reject_key_material(&args)?;
    let token = req_str(&args, "token_contract_address")?;
    let buyer = req_str(&args, "buyer_wallet_address")?;
    let shell = req_u128(&args, "shell_amount")?;
    if shell == 0 {
        bail!("shell_amount must be > 0");
    }
    let native_gas = opt_u128(&args, "native_value_vmshell").unwrap_or(AIREGISTRY_GAS_VMSHELL);
    let ctx = local_context()?;
    let abi = Contract::TokenContract.abi_json();
    let payload = encode_internal_payload(&ctx, abi, "buyTokens", json!({})).await?;

    // Chain preflight (no keys): best-effort lot + entitlement snapshot.
    let lot = get_lot(state, with_dapp_id(token, None, &args)).await.ok();
    let entitlement_before = get_entitlement(state, with_dapp_id(token, Some(buyer), &args))
        .await
        .ok();

    Ok(json!({
        "intent": {
            "kind": "airegistry.buy_tokens",
            "flow": "payload_only",
            "network": state.network.name,
            "token_contract_address": token,
            "buyer_wallet_address": buyer,
            "method": "buyTokens",
            "shell_amount": shell.to_string(),
            "native_value_vmshell": native_gas.to_string(),
            "currency": { "id": SHELL_CURRENCY_ID, "symbol": "SHELL" },
            "payload_boc_b64": payload.clone(),
            "expected_package_sha256": opt_str(&args, "expected_package_sha256"),
            "client_intent_id": opt_str(&args, "client_intent_id"),
        },
        // The wallet must attach BOTH ECC[2] SHELL (payment) and native vmshell
        // (gas) along with the body — buyTokens has no payload amount.
        "wallet_action": {
            "type": "shell_transfer_with_body",
            "to": token,
            "shell_amount": shell.to_string(),
            "native_value_vmshell": native_gas.to_string(),
            "body_boc_b64": payload,
            "required_capability": "transfer_with_custom_body",
        },
        "human_summary": {
            "title": "Buy AI Registry usage tokens",
            "recipient": token,
            "signer_wallet": buyer,
            "buy_tokens_amount_shell": shell.to_string(),
            "gas_vmshell": native_gas.to_string(),
            "currency": "SHELL",
            "expected_result": "buyer wallet becomes current buyer; reserved tokens increase",
        },
        "preflight": { "lot": lot, "entitlement_before": entitlement_before },
        "notes": "buyTokens() has no arguments — the buy amount is the attached ECC[2] SHELL value (wallet_action.shell_amount), not a payload field. expected_package_sha256 is echoed only; the lot has no on-chain package hash, so verify it via airegistry_get_manifest.",
    }))
}

/// Prepare a frontend-safe **cancel** (refund) intent (Flow A). The payout is
/// ALWAYS the buyer wallet — never caller-overridable (refund-escape safety).
/// The wallet attaches only gas (no SHELL) with the body.
async fn prepare_user_cancel(state: &AppState, args: Value) -> Result<Value> {
    reject_key_material(&args)?;
    let token = req_str(&args, "token_contract_address")?;
    let buyer = req_str(&args, "buyer_wallet_address")?;
    let native_gas = opt_u128(&args, "native_value_vmshell").unwrap_or(AIREGISTRY_GAS_VMSHELL);
    let ctx = local_context()?;
    let abi = Contract::TokenContract.abi_json();
    // payoutAddress is fixed to the buyer wallet (a real payload argument here).
    let payload =
        encode_internal_payload(&ctx, abi, "cancel", json!({ "payoutAddress": buyer })).await?;

    let entitlement_before = get_entitlement(state, with_dapp_id(token, Some(buyer), &args))
        .await
        .ok();

    Ok(json!({
        "intent": {
            "kind": "airegistry.cancel",
            "flow": "payload_only",
            "network": state.network.name,
            "token_contract_address": token,
            "buyer_wallet_address": buyer,
            "method": "cancel",
            "payout_wallet_address": buyer,
            "native_value_vmshell": native_gas.to_string(),
            "payload_boc_b64": payload.clone(),
            "client_intent_id": opt_str(&args, "client_intent_id"),
        },
        "wallet_action": {
            "type": "shell_transfer_with_body",
            "to": token,
            "native_value_vmshell": native_gas.to_string(),
            "body_boc_b64": payload,
            "required_capability": "transfer_with_custom_body",
        },
        "human_summary": {
            "title": "Cancel reservation / refund unused tokens",
            "recipient": token,
            "signer_wallet": buyer,
            "payout_wallet_address": buyer,
            "expected_result": "remaining reserved tokens refunded to the buyer wallet; seller keeps already-billed sessions",
        },
        "preflight": { "entitlement_before": entitlement_before },
    }))
}

/// Verify whether a buyer wallet is ready to start a package instance, composing
/// chain reads into a single stable `status`:
/// `verified` | `not_current_buyer` | `insufficient_reserved` | `lot_unavailable`
/// | `chain_unavailable` (`ready == status == "verified"`). Pure read; available
/// in `--read-only` and `--stateless-payments`.
///
/// Deliberately NO `package_hash_mismatch` (the lot has no on-chain package hash
/// — `getConfig` is tick/fee/maxReserved only; verify `expected_package_sha256`
/// via `airegistry_get_manifest`) and NO `expired`/`revoked` (those are backend
/// policy, not AI Registry chain facts).
async fn verify_payment_readiness(state: &AppState, args: Value) -> Result<Value> {
    reject_key_material(&args)?;
    let token = req_str(&args, "token_contract_address")?;
    let buyer = req_str(&args, "buyer_wallet_address")?;
    let min_reserved = opt_u128(&args, "minimum_reserved").unwrap_or(1);

    // Read lot, then entitlement; classify any failure into a stable status.
    #[allow(clippy::type_complexity)]
    let (status, detail, lot, ent): (&str, Option<String>, Option<Value>, Option<Value>) =
        match get_lot(state, with_dapp_id(token, None, &args)).await {
            Err(e) => {
                let msg = e.to_string();
                let s = if msg.contains("not found") || msg.contains("not active") {
                    "lot_unavailable"
                } else {
                    "chain_unavailable"
                };
                (s, Some(msg), None, None)
            }
            Ok(lot) => {
                match get_entitlement(state, with_dapp_id(token, Some(buyer), &args)).await {
                    Err(e) => ("chain_unavailable", Some(e.to_string()), Some(lot), None),
                    Ok(ent) => {
                        let is_current = ent
                            .get("is_current_buyer")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let reserved = val_u128(ent.get("reserved")).unwrap_or(0);
                        let s = if !is_current {
                            "not_current_buyer"
                        } else if reserved < min_reserved {
                            "insufficient_reserved"
                        } else {
                            "verified"
                        };
                        (s, None, Some(lot), Some(ent))
                    }
                }
            }
        };

    let entitlement = ent.as_ref().map(|e| {
        json!({
            "is_current_buyer": e.get("is_current_buyer"),
            "reserved": e.get("reserved"),
            "consume_calls": e.get("consume_calls"),
            "seller_owed": e.get("seller_owed"),
        })
    });

    Ok(json!({
        "ready": status == "verified",
        "status": status,
        "detail": detail,
        "token_contract_address": token,
        "buyer_wallet_address": buyer,
        "minimum_reserved": min_reserved.to_string(),
        "entitlement": entitlement,
        "lot": lot,
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "expected_package_sha256": opt_str(&args, "expected_package_sha256"),
        "package_hash_note": "the lot carries no on-chain package hash; verify expected_package_sha256 via airegistry_get_manifest (package_hash_mismatch is not a chain status)",
    }))
}

mod schemas;
pub use schemas::list_airegistry_tools;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_by_name_maps_all() {
        for n in [
            "SuperRoot",
            "RootModel",
            "TokenContract",
            "ManifestMetadata",
        ] {
            contract_by_name(n).unwrap();
        }
        assert!(contract_by_name("Nope").is_err());
    }

    // ---- list_marketplace SuperRoot resolution (explicit / default / missing) ----

    #[test]
    fn resolve_super_root_explicit_arg_wins() {
        // Explicit arg works with no configured default…
        let cfg = AiRegistryConfig::shellnet();
        assert_eq!(
            resolve_super_root(&json!({ "super_root_address": "0:abc" }), &cfg).unwrap(),
            "0:abc"
        );
        // …and also takes precedence over a configured default.
        let mut cfg2 = AiRegistryConfig::shellnet();
        cfg2.super_root_address = Some("0:default".into());
        assert_eq!(
            resolve_super_root(&json!({ "super_root_address": "0:explicit" }), &cfg2).unwrap(),
            "0:explicit"
        );
    }

    #[test]
    fn resolve_super_root_falls_back_to_configured_default() {
        let mut cfg = AiRegistryConfig::shellnet();
        cfg.super_root_address = Some("0:configured".into());
        assert_eq!(
            resolve_super_root(&json!({}), &cfg).unwrap(),
            "0:configured"
        );
    }

    #[test]
    fn resolve_super_root_errors_when_no_default() {
        // No arg, no configured default → clear error.
        let cfg = AiRegistryConfig::shellnet();
        let err = resolve_super_root(&json!({}), &cfg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no SuperRoot"), "got: {err}");
        assert!(err.contains("super_root_address") || err.contains("airegistry-super-root"));
        // An empty configured default is treated as absent.
        let mut cfg2 = AiRegistryConfig::shellnet();
        cfg2.super_root_address = Some(String::new());
        assert!(resolve_super_root(&json!({}), &cfg2).is_err());
    }

    // ---- stateless user-signed payments (Flow A) ----

    #[test]
    fn reject_key_material_blocks_secrets() {
        // Clean args pass.
        assert!(reject_key_material(
            &json!({ "token_contract_address": "0:x", "shell_amount": "1" })
        )
        .is_ok());
        // Any key-ish field is refused.
        for bad in [
            "secret",
            "private_key",
            "privkey",
            "signer_ref",
            "signer",
            "seed_phrase",
            "wallet_mnemonic",
        ] {
            assert!(
                reject_key_material(&json!({ bad: "v" })).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn flow_a_encodes_inner_payloads() {
        // The inner TokenContract payloads are a LOCAL TVM encode (no network).
        let ctx = local_context().unwrap();
        let abi = Contract::TokenContract.abi_json();
        let buy = encode_internal_payload(&ctx, abi, "buyTokens", json!({}))
            .await
            .unwrap();
        assert!(!buy.is_empty());
        let cancel = encode_internal_payload(
            &ctx,
            abi,
            "cancel",
            json!({ "payoutAddress": "0:1111111111111111111111111111111111111111111111111111111111111111" }),
        )
        .await
        .unwrap();
        assert!(!cancel.is_empty());
        // Distinct calls ⇒ distinct bodies.
        assert_ne!(buy, cancel);
    }

    #[test]
    fn resolve_abi_and_tvc() {
        assert!(resolve_abi(&json!({ "contract": "TokenContract" }))
            .unwrap()
            .contains("buyTokens"));
        assert_eq!(resolve_abi(&json!({ "abi_json": "{}" })).unwrap(), "{}");
        assert!(!resolve_tvc(&json!({ "contract": "RootModel" }))
            .unwrap()
            .is_empty());
        assert!(resolve_abi(&json!({})).is_err());
    }

    #[test]
    fn numeric_and_hex_helpers() {
        assert_eq!(req_u128(&json!({ "v": "42" }), "v").unwrap(), 42);
        assert_eq!(req_u128(&json!({ "v": 42 }), "v").unwrap(), 42);
        assert!(req_u16(&json!({ "v": 70000 }), "v").is_err());
        assert_eq!(hexparam("abcd"), "0xabcd");
        assert_eq!(hexparam("0xabcd"), "0xabcd");
    }

    #[test]
    fn treasury_tx_origin_validates_before_submit() {
        let good = "ab".repeat(32); // 64 hex
                                    // explicit valid dapp_id → Explicit (normalised, no 0: prefix)
        match treasury_tx_read_origin(
            &json!({ "treasury_dapp_id": format!("0:{good}") }),
            None,
            true,
        )
        .unwrap()
        {
            AccountOrigin::Explicit { dapp_id } => assert_eq!(dapp_id, good),
            _ => panic!("expected Explicit"),
        }
        // MALFORMED dapp_id must error here (before any on-chain submit), not in
        // the post-submit getter read.
        assert!(
            treasury_tx_read_origin(&json!({ "treasury_dapp_id": "0:tooshort" }), None, true)
                .is_err()
        );
        assert!(treasury_tx_read_origin(&json!({ "treasury_dapp_id": "zz" }), None, true).is_err());
        // override with no way to determine the dapp id → rejected
        assert!(treasury_tx_read_origin(&json!({}), None, true).is_err());
        // swarm_root path → SwarmChild (validated)
        match treasury_tx_read_origin(&json!({}), Some(&format!("0:{good}")), false).unwrap() {
            AccountOrigin::SwarmChild { dapp_id } => assert_eq!(dapp_id, good),
            _ => panic!("expected SwarmChild"),
        }
        assert!(treasury_tx_read_origin(&json!({}), Some("0:bad"), false).is_err());
        // metadata path, no swarm_root, no override → self-originating
        assert!(matches!(
            treasury_tx_read_origin(&json!({}), None, false).unwrap(),
            AccountOrigin::SelfOriginating
        ));
    }

    #[test]
    fn checked_conversions_reject_out_of_range() {
        // ABI-range rejection — no silent truncation (uint8 maxReservedSessions=300
        // must NOT become 44; uint64 nonce overflow must NOT wrap).
        assert_eq!(req_u8(&json!({ "v": 200 }), "v").unwrap(), 200);
        let e = req_u8(&json!({ "v": 300 }), "v").unwrap_err().to_string();
        assert!(e.contains("uint8") && e.contains("300"), "{e}");
        assert_eq!(req_u64(&json!({ "v": "5" }), "v").unwrap(), 5);
        let big = (u64::MAX as u128 + 1).to_string();
        assert!(req_u64(&json!({ "v": big }), "v")
            .unwrap_err()
            .to_string()
            .contains("uint64"));
    }
}
