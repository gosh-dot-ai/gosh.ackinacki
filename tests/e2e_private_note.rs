// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT
#![cfg(feature = "private-note")]

//! Live validation for the `private-note` feature against shellnet.
//!
//! These are `#[ignore]` (require network / heavy halo2). They cover the live
//! read path (on-chain RootPN getters), the `sk_u` (CSPRNG) → `skUCommit`
//! (poseidon) binding, SRS generation, AND the FULL money path: deploy a fresh
//! UpdateCustodianMultisigWallet via the shellnet Giver, fund it with ECC[2]
//! SHELL, then mint a real PrivateNote (voucher → halo2 proof → deployPrivateNote
//! → sendEccShellToPrivateNote).
//!
//! Run: `cargo test --features private-note --test e2e_private_note -- --ignored --nocapture`

use std::time::Duration;

use gosh_ackinacki::airegistry::deploy::{build_deploy, local_context};
use gosh_ackinacki::private_note::artifacts::ROOT_PN_ABI_JSON;
use gosh_ackinacki::private_note::halo2::paths::Halo2Paths;
use gosh_ackinacki::private_note::halo2::sk_commit::compute_sk_u_commit_hex;
use gosh_ackinacki::private_note::proof::random_secret_key;
use gosh_ackinacki::private_note::{
    deploy_private_note_from_multisig, DeployPrivateNoteParams, Nominal, TokenType,
};
use gosh_ackinacki::sdk::{Address, ChainClient, KeyPair};
use gosh_ackinacki::wallet::contracts::{MULTISIG_ABI_JSON, MULTISIG_TVC};
use gosh_ackinacki::wallet::giver::GiverClient;
use serde_json::json;

const SHELLNET: &str = "https://shellnet.ackinacki.org";
const GIVER_SECRET: &str = "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b";
/// dexdo's shellnet RootPN premine — supplied by the CALLER now (the library no
/// longer hardcodes it), so the tests provide it here.
const SHELLNET_ROOT_PN: &str = "0:1010101010101010101010101010101010101010101010101010101010101010";
const SHELLNET_ROOT_PN_DAPP_ID: &str = "0";

#[tokio::test]
#[ignore]
async fn live_rootpn_is_active_and_getters_run() {
    let client = ChainClient::shellnet().unwrap();
    let root_pn = Address::parse(SHELLNET_ROOT_PN).unwrap();

    // 1. The premine RootPN must be Active on shellnet.
    let acc = client
        .get_account(&root_pn)
        .await
        .expect("get RootPN account")
        .expect("RootPN exists");
    eprintln!(
        "RootPN {root_pn}: status={} native={}",
        acc.status, acc.balance
    );
    assert!(acc.is_active(), "RootPN must be Active");

    // 2. Run real getters against the on-chain code (validates ABI + read path).
    let version = client
        .run_getter(&root_pn, ROOT_PN_ABI_JSON, "getVersion", json!({}))
        .await
        .expect("run getVersion")
        .expect("getVersion output");
    eprintln!("RootPN.getVersion -> {version}");

    let details = client
        .run_getter(&root_pn, ROOT_PN_ABI_JSON, "getDetails", json!({}))
        .await
        .expect("run getDetails")
        .expect("getDetails output");
    eprintln!("RootPN.getDetails -> {details}");

    // getPrivateNoteAddress is a pure address derivation — call with a dummy hash.
    let derived = client
        .run_getter(
            &root_pn,
            ROOT_PN_ABI_JSON,
            "getPrivateNoteAddress",
            json!({ "depositIdentifierHash": "1" }),
        )
        .await
        .expect("run getPrivateNoteAddress")
        .expect("getPrivateNoteAddress output");
    let pn_addr = derived
        .get("privateNoteAddress")
        .and_then(|v| v.as_str())
        .expect("privateNoteAddress field");
    eprintln!("RootPN.getPrivateNoteAddress(1) -> {pn_addr}");
    assert!(
        Address::parse(pn_addr).is_ok(),
        "derived PrivateNote address must be a valid 0:hex address"
    );
}

#[test]
fn sk_u_csprng_to_skucommit_binding() {
    // The security fix: sk_u is CSPRNG-sampled, distinct each call, a valid
    // BN254 Fr, and binds to a poseidon commitment.
    let a = random_secret_key();
    let b = random_secret_key();
    assert_ne!(a, b, "two CSPRNG sk_u samples must differ");
    assert_eq!(a.len(), 64, "sk_u is 32 bytes / 64 hex");
    let commit = compute_sk_u_commit_hex(&a).expect("poseidon([sk_u, 0]) must compute");
    assert_eq!(commit.len(), 64, "skUCommit is a 32-byte field element");
    // Deterministic: same sk_u → same commit.
    assert_eq!(commit, compute_sk_u_commit_hex(&a).unwrap());
}

#[test]
#[ignore]
fn live_halo2_srs_generation_and_paths_validate() {
    // Heaviest self-serve halo2 validation (no funded wallet needed): generate
    // the KZG SRS via halo2_base::gen_srs and confirm Halo2Paths::validate()
    // accepts the artifact layout. Proves the proving graph's parameter path works.
    use gosh_ackinacki::private_note::halo2::paths::Halo2Paths;
    let dir = std::env::temp_dir().join(format!("pn_srs_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = Halo2Paths {
        srs_dir: dir.clone(),
        prover_cache_dir: dir.join("cache"),
        fixture_dir: dir.join("fixtures"),
    };
    assert!(!paths.srs_exists(), "fresh dir has no SRS");
    eprintln!("generating KZG SRS (k=19, ~64MB)…");
    let t = std::time::Instant::now();
    paths.ensure_srs();
    eprintln!(
        "SRS generated in {:.1}s, exists={}",
        t.elapsed().as_secs_f64(),
        paths.srs_exists()
    );
    assert!(paths.srs_exists(), "ensure_srs must produce the SRS file");
    paths
        .validate()
        .expect("paths validate after SRS generation");
    std::fs::remove_dir_all(&dir).ok();
}

/// FULL money path: deploy a fresh 1-of-1 UpdateCustodianMultisigWallet via the
/// shellnet Giver, fund it with ECC[2] SHELL, and mint a real SHELL PrivateNote
/// end to end (voucher deposit → halo2 proof → deployPrivateNote → SHELL gas
/// voucher → sendEccShellToPrivateNote → getDetails sanity). Heavy: SRS gen +
/// keygen + chain layer wait (~15-20 min). Self-funded — needs only the Giver.
#[tokio::test]
#[ignore]
async fn live_full_private_note_mint_via_giver() {
    let client = ChainClient::shellnet().unwrap();
    let cfg = gosh_ackinacki::config::AiRegistryConfig::shellnet();
    let http = reqwest::Client::new();
    let ctx = local_context().unwrap();
    let giver = GiverClient::new(
        ctx.clone(),
        cfg.giver_address.as_ref().unwrap(),
        cfg.giver_pubkey.as_ref().unwrap(),
        GIVER_SECRET,
        SHELLNET,
        http.clone(),
    );

    // 1. Fresh 1-of-1 operational wallet (reqConfirms=1 → sendTransaction is immediate).
    let wallet = KeyPair::generate();
    let deploy_msg = build_deploy(
        &ctx,
        MULTISIG_ABI_JSON,
        MULTISIG_TVC,
        json!({}),
        json!({
            "owners_pubkey": [format!("0x{}", wallet.public_hex())],
            "owners_address": [],
            "reqConfirms": 1,
            "reqConfirmsData": 1,
            "value": "0",
        }),
        wallet.public_hex(),
        wallet.secret_hex(),
    )
    .await
    .expect("build multisig deploy");
    eprintln!("operational wallet → {}", deploy_msg.address);

    // 2. Giver funds the deploy address (native vmshell), then deploy → Active.
    giver
        .fund_deploy_address(&deploy_msg.address, 200_000_000_000)
        .await
        .expect("giver fund deploy address");
    let wallet_addr = client
        .deploy(&deploy_msg, 180)
        .await
        .expect("deploy operational wallet to Active");
    eprintln!("  wallet Active: {wallet_addr}");

    // 3. Giver funds the wallet with ECC[2] SHELL: N100 deposit (1e11) + SHELL gas
    //    voucher (1e11) + headroom.
    giver
        .send_shell(&deploy_msg.address, 500_000_000_000)
        .await
        .expect("giver fund wallet with ECC[2] SHELL");
    eprintln!("  funded wallet with 5e11 ECC[2] SHELL");
    tokio::time::sleep(Duration::from_secs(8)).await;
    let bal = client.get_account(&wallet_addr).await.unwrap().unwrap();
    eprintln!(
        "  wallet balances: native={} shell={}",
        bal.balance,
        bal.shell()
    );
    assert!(
        bal.shell() >= 200_000_000_000,
        "wallet must hold the deposit+gas SHELL"
    );

    // 4. SRS / prover cache in a persistent dir (regenerated on first run).
    let halo2_dir = std::path::PathBuf::from("target/pn_e2e_halo2");
    let halo2_paths = Halo2Paths {
        srs_dir: halo2_dir.clone(),
        prover_cache_dir: halo2_dir.join("cache"),
        fixture_dir: halo2_dir.join("fixtures"),
    };
    if !halo2_paths.srs_exists() {
        eprintln!("generating KZG SRS (one-time, ~6 min)…");
        halo2_paths.ensure_srs();
    }
    halo2_paths.validate().expect("halo2 paths valid");

    // 5. Mint the PrivateNote end to end.
    eprintln!("minting N100 SHELL PrivateNote (voucher → proof → deploy → fund)…");
    let result = deploy_private_note_from_multisig(
        &client,
        DeployPrivateNoteParams {
            root_pn_address: Address::parse(SHELLNET_ROOT_PN).unwrap(),
            forward_dapp_id: SHELLNET_ROOT_PN_DAPP_ID.to_string(),
            multisig_address: wallet_addr.clone(),
            multisig_keys: wallet,
            nominal: Nominal::N100,
            token_type: TokenType::Shell,
            halo2_paths,
        },
    )
    .await
    .expect("full PrivateNote mint");

    eprintln!(
        "✓ MINTED PrivateNote: addr={} dih={} value={} shell_funded={} sanity_checked={}",
        result.pn_address,
        result.deposit_identifier_hash,
        result.raw_value,
        result.shell_funded,
        result.sanity_checked
    );
    assert!(result.shell_funded && result.sanity_checked);
    let pn = Address::parse(&result.pn_address).unwrap();
    assert!(
        client.get_account(&pn).await.unwrap().unwrap().is_active(),
        "minted PrivateNote must be Active on-chain"
    );
}

#[test]
fn wallet_tvc_code_hashes() {
    use tvm_block::Deserializable;
    for (name, tvc) in [
        (
            "UpdateCustodianMultisigWallet",
            &include_bytes!("../contracts/UpdateCustodianMultisigWallet.tvc")[..],
        ),
        (
            "SwarmMultisigWallet",
            &include_bytes!("../contracts/swarm/SwarmMultisigWallet.tvc")[..],
        ),
    ] {
        let cell = tvm_types::read_single_root_boc(tvc).unwrap();
        let si = tvm_block::StateInit::construct_from_cell(cell).unwrap();
        if let Some(code) = si.code() {
            eprintln!("{name} code_hash = {:x}", code.repr_hash());
        }
    }
}

/// dexdo-specs#196 fail-fast: minting from a wallet that is NOT an
/// UpdateCustodianMultisigWallet must return an explicit Err FAST — not the old
/// silent ~480s voucher-event timeout. Uses the Active RootPN premine as a
/// stand-in wrong-type address (its code_hash != the wallet's 8470e1da), so no
/// wallet deploy / halo2 is needed. Proves the guard triggers before any voucher.
#[tokio::test]
#[ignore]
async fn live_mint_fails_fast_on_wrong_wallet_type() {
    let client = ChainClient::shellnet().unwrap();
    let wrong_type = Address::parse(SHELLNET_ROOT_PN).unwrap(); // Active, not an UpdateCustodian wallet
    let halo2_dir = std::path::PathBuf::from("target/pn_e2e_halo2");
    let started = std::time::Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(60),
        deploy_private_note_from_multisig(
            &client,
            DeployPrivateNoteParams {
                root_pn_address: Address::parse(SHELLNET_ROOT_PN).unwrap(),
                forward_dapp_id: SHELLNET_ROOT_PN_DAPP_ID.to_string(),
                multisig_address: wrong_type,
                multisig_keys: KeyPair::generate(),
                nominal: Nominal::N100,
                token_type: TokenType::Shell,
                halo2_paths: Halo2Paths {
                    srs_dir: halo2_dir.clone(),
                    prover_cache_dir: halo2_dir.join("cache"),
                    fixture_dir: halo2_dir.join("fixtures"),
                },
            },
        ),
    )
    .await
    .expect("must resolve well under the old 480s timeout (fail-fast)");
    let elapsed = started.elapsed();
    let err = res
        .expect_err("wrong wallet type must be rejected")
        .to_string();
    eprintln!("fail-fast in {:.1}s → {err}", elapsed.as_secs_f64());
    assert!(
        elapsed < Duration::from_secs(30),
        "must fail fast, took {elapsed:?}"
    );
    assert!(
        err.contains("code_hash") && err.contains("UpdateCustodianMultisigWallet"),
        "error must name the code_hash mismatch + required type: {err}"
    );
    assert!(!err.contains("480"), "must NOT be the old voucher timeout");
}
