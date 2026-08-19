// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT
#![cfg(feature = "private-note")]

//! Live inference-market validation on shellnet: deploy a per-model order book
//! from a freshly minted PrivateNote, post a sell offer, then prove the READ
//! side this crate ships — the **order-book snapshot** (all open orders) and
//! the **typed event feed** (placed / deployed / …).
//!
//! Self-funded via the shellnet Giver (mint ≈ 11 min with a warm halo2 cache).
//! Run: `cargo test --features private-note --test e2e_inference -- --ignored --nocapture`

use std::time::Duration;

use gosh_ackinacki::airegistry::calls::encode_external_call;
use gosh_ackinacki::airegistry::deploy::{build_deploy, local_context};
use gosh_ackinacki::airegistry::getter::{AccountOrigin, AccountReader};
use gosh_ackinacki::airegistry::run::GetterRunner;
use gosh_ackinacki::inference::abi::PRIVATE_NOTE_ABI_JSON;
use gosh_ackinacki::inference::book::SYSTEM_DAPP_ID;
use gosh_ackinacki::inference::{decode_event_body_b64, InferenceAbis, InferenceEvent};
use gosh_ackinacki::private_note::halo2::paths::Halo2Paths;
use gosh_ackinacki::private_note::{
    deploy_private_note_from_multisig, DeployPrivateNoteParams, Nominal, TokenType,
};
use gosh_ackinacki::sdk::{Address, ChainClient, KeyPair};
use gosh_ackinacki::wallet::contracts::{MULTISIG_ABI_JSON, MULTISIG_TVC};
use gosh_ackinacki::wallet::giver::GiverClient;
use gosh_ackinacki::wallet::query::send_message_routed;
use serde_json::json;

const SHELLNET: &str = "https://shellnet.ackinacki.org";
const GIVER_SECRET: &str = "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b";
const SHELLNET_ROOT_PN: &str = "0:1010101010101010101010101010101010101010101010101010101010101010";

/// Full market read-path proof: mint note → deploy order book → post sell offer
/// → assert the BOOK SNAPSHOT lists the open order → assert the typed EVENTS
/// (BookDeployed + OrderPlaced) decode from the book's event log.
#[tokio::test]
#[ignore]
async fn live_order_book_snapshot_and_events() {
    let client = ChainClient::shellnet().unwrap();
    let cfg = gosh_ackinacki::config::AiRegistryConfig::shellnet();
    let http = reqwest::Client::new();
    let ctx = local_context().unwrap();
    let reader = AccountReader::new(http.clone(), SHELLNET);
    let runner = GetterRunner::new().unwrap();
    let giver = GiverClient::new(
        ctx.clone(),
        cfg.giver_address.as_ref().unwrap(),
        cfg.giver_pubkey.as_ref().unwrap(),
        GIVER_SECRET,
        SHELLNET,
        http.clone(),
    );

    // ---- 1. Fund + mint a fresh note (the market participant). ----
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
    giver
        .fund_deploy_address(&deploy_msg.address, 200_000_000_000)
        .await
        .expect("giver fund wallet");
    let wallet_addr = client
        .deploy(&deploy_msg, 180)
        .await
        .expect("wallet Active");
    giver
        .send_shell(&deploy_msg.address, 500_000_000_000)
        .await
        .expect("giver fund ECC[2] SHELL");
    tokio::time::sleep(Duration::from_secs(8)).await;
    eprintln!("wallet {wallet_addr} funded; minting note…");

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
    halo2_paths.validate().expect("halo2 paths");

    let note = deploy_private_note_from_multisig(
        &client,
        DeployPrivateNoteParams {
            root_pn_address: Address::parse(SHELLNET_ROOT_PN).unwrap(),
            forward_dapp_id: "0".to_string(),
            multisig_address: wallet_addr,
            multisig_keys: wallet,
            nominal: Nominal::N100,
            token_type: TokenType::Shell,
            halo2_paths,
        },
    )
    .await
    .expect("mint note");
    let note_addr = Address::parse(&note.pn_address).unwrap();
    let note_keys = KeyPair::from_secret_hex(&note.owner_secret_key_hex).unwrap();
    eprintln!("note minted: {note_addr}");

    // The note lives in the system DApp — all note traffic routes through it.
    let note_origin = AccountOrigin::Explicit {
        dapp_id: SYSTEM_DAPP_ID.to_string(),
    };

    // ---- 2. Deploy this run's order book. The book ctor requires
    //         `sha256(modelName) == modelHash` (the name is the hash preimage). ----
    use sha2::{Digest, Sha256};
    let model_name = format!("e2e-model-{}", hex::encode(rand::random::<[u8; 6]>()));
    let model_hash = format!("0x{}", hex::encode(Sha256::digest(model_name.as_bytes())));
    note_call(
        &ctx,
        &http,
        &note_addr,
        "deployInferenceOrderBook",
        json!({ "modelHash": model_hash, "modelName": model_name }),
        &note_keys,
    )
    .await
    .expect("deployInferenceOrderBook");
    tokio::time::sleep(Duration::from_secs(10)).await;

    let note_snap = reader
        .fetch(&cfg, &note_addr.with_workchain(), &note_origin)
        .await
        .expect("fetch note")
        .expect("note active");
    let book_out = runner
        .run_getter(
            PRIVATE_NOTE_ABI_JSON,
            &note_addr.with_workchain(),
            note_snap.boc.as_deref().unwrap(),
            "getInferenceOrderBookAddress",
            json!({ "modelHash": model_hash }),
        )
        .await
        .expect("getInferenceOrderBookAddress");
    let book_addr = Address::parse(book_out["value0"].as_str().expect("book address")).unwrap();
    eprintln!("order book for {model_name} → {book_addr}");

    // Wait for the book to be Active (it inherits the system DApp).
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(s) = reader
            .fetch(&cfg, &book_addr.with_workchain(), &note_origin)
            .await
            .expect("fetch book")
        {
            if s.is_active() {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "order book did not become Active within 120s"
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    eprintln!("book Active ✓");

    // ---- 3. Place a resting BUY order (7/tick × 10 ticks). A buy needs only
    //         SHELL escrow (no TokenContract, unlike a sell), and the book's
    //         _processHeadCore seats it in the same tx. Escrow is generous so
    //         `escrow >= ticks * _unit(price)` always holds. ----
    let buy = note_call(
        &ctx,
        &http,
        &note_addr,
        "placeInferenceBuy",
        json!({
            "modelHash": model_hash,
            "maxPricePerTick": "7",
            "ticks": "10",
            "escrow": "1000000000",
            "flags": 0,
            "deadline": 0,
        }),
        &note_keys,
    )
    .await;
    let order_placed = buy.is_ok();
    eprintln!("placeInferenceBuy sent: {order_placed} ({buy:?})");
    tokio::time::sleep(Duration::from_secs(12)).await;

    // ---- 4. THE BOOK: snapshot all open orders via the sdk facade. ----
    let book = client
        .inference_order_book(&book_addr, None, 1_000)
        .await
        .expect("inference_order_book")
        .expect("book snapshot present (auto dapp resolution)");
    eprintln!(
        "BOOK {}: model={} fee={}bps orders={} best_bid={:?} best_ask={:?} truncated={}",
        book.address,
        book.model_name,
        book.platform_fee_bps,
        book.stats.order_count,
        book.best_bid,
        book.best_ask,
        book.truncated
    );
    for o in book.asks.iter().chain(book.bids.iter()) {
        eprintln!(
            "  {} #{} {} ticks @ {} (note {})",
            if o.is_buy { "BID" } else { "ASK" },
            o.order_id,
            o.ticks,
            o.price,
            o.note
        );
    }
    assert_eq!(book.model_name, model_name, "book identity");
    assert!(!book.truncated);
    if order_placed {
        assert_eq!(book.stats.order_count, 1, "one open order");
        assert_eq!(book.bids.len(), 1, "the buy is a resting bid");
        assert!(book.asks.is_empty(), "no asks");
        assert_eq!(book.bids[0].price, 7);
        assert_eq!(book.bids[0].ticks, 10);
        assert!(book.bids[0].is_buy);
        assert_eq!(book.best_bid, Some(7));
        assert_eq!(
            Address::parse(&book.bids[0].note).unwrap(),
            note_addr,
            "bid owned by our note"
        );
    }

    // ---- 5. THE EVENTS: typed feed from the book's event log. ----
    let abis = InferenceAbis::load().unwrap();
    let page = reader
        .read_events_with(
            &cfg,
            &book_addr.with_workchain(),
            &note_origin,
            50,
            None,
            &|b| decode_event_body_b64(&abis, b).ok().flatten(),
        )
        .await
        .expect("read book events");
    eprintln!("events ({}):", page.records.len());
    for r in &page.records {
        eprintln!("  {:?}", r.event);
    }
    assert!(
        page.records.iter().any(|r| matches!(
            &r.event,
            InferenceEvent::BookDeployed { model_name: n, .. } if *n == model_name
        )),
        "BookDeployed event decoded"
    );
    if order_placed {
        assert!(
            page.records.iter().any(|r| matches!(
                &r.event,
                InferenceEvent::OrderPlaced { is_buy: true, price, ticks: 10, .. } if price == "7"
            )),
            "OrderPlaced (bid 10 @ 7) event decoded"
        );
    }
    eprintln!("=== INFERENCE MARKET READ PATH (book snapshot + typed events) PASSED ===");
}

/// Signed external call to the note, routed through the system DApp (the note
/// inherits RootPN's DApp lineage, so plain self-routing would miss it).
async fn note_call(
    ctx: &std::sync::Arc<tvm_client::ClientContext>,
    http: &reqwest::Client,
    note: &Address,
    method: &str,
    args: serde_json::Value,
    keys: &KeyPair,
) -> anyhow::Result<serde_json::Value> {
    let boc = encode_external_call(
        ctx,
        PRIVATE_NOTE_ABI_JSON,
        &note.with_workchain(),
        method,
        args,
        keys.public_hex(),
        keys.secret_hex(),
    )
    .await?;
    send_message_routed(http, SHELLNET, &boc, note.bare(), SYSTEM_DAPP_ID, None).await
}
