// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Lean SDK demo — talk to Acki Nacki over the Block Manager HTTP/GraphQL API
//! with NO node / MsQuic, using only `gosh_ackinacki::sdk`.
//!
//! This is exactly what a thin external consumer gets with
//! `gosh-ackinacki = { git = "…", default-features = false }`.
//!
//! Run: `cargo run --example sdk_lean_client`

use anyhow::Result;
use gosh_ackinacki::sdk::{Address, ChainClient, KeyPair};

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Connect to shellnet (Block Manager HTTP — no node spun up).
    let client = ChainClient::shellnet()?;
    println!("connected to {}", client.endpoint());

    // 2. Is the chain actually producing blocks? A halted chain still serves
    //    reads, so this tells "network is down" apart from "my write was bad".
    let live = client.chain_liveness().await?;
    println!(
        "chain liveness: newest block #{} is {}s old -> {}",
        live.latest_seq_no,
        live.latest_block_age_secs,
        if live.is_live() { "LIVE" } else { "HALTED" }
    );

    // 3. Read an account with balances — the system Giver at 0:1111…
    let giver = Address::parse(&"1".repeat(64))?;
    match client.get_account(&giver).await? {
        Some(acc) => println!(
            "{}: status={} native={} SHELL(ECC2)={}",
            acc.address,
            acc.status,
            acc.balance,
            acc.shell()
        ),
        None => println!("{giver} not found"),
    }

    // 4. A fresh signing identity (ed25519) — the only key needed to sign
    //    transactions. Sealed-secret delivery (X25519 / gosh.memory) is a
    //    separate concern and intentionally not part of this client.
    let keys = KeyPair::generate();
    println!("generated signing key: {}", keys.public());

    // To WRITE you'd either build a deploy with
    // `gosh_ackinacki::airegistry::deploy::build_deploy(...)` then
    // `client.deploy(&msg, 150).await?`, or sign a call directly with
    // `client.call(&addr, abi_json, "method", args, &keys).await?`.
    Ok(())
}
