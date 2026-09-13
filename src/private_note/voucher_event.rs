// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! GraphQL helpers for capturing live `RootPN.VoucherGenerated` ext-out
//! messages and waiting for the chain to reach a desired block height.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::Deserialize;
use tvm_abi::TokenValue;
use tvm_types::SliceData;

use crate::private_note::artifacts;
use crate::private_note::proof::parse_u256;
use crate::sdk::Address;

/// External destination address every `VoucherGenerated` event lands on,
/// computed by `RootPN.sol::generateVoucher`.
pub const VOUCHER_EVENT_DST: &str =
    ":0000000000000000000000000000000000000000000000000000000000000087";

const GQL_EXTOUT_MESSAGES: &str = r#"
    query($accountId: String!, $dappId: String!, $last: Int!) {
      blockchain {
        account(account_id: $accountId, dapp_id: $dappId) {
          messages(msg_type: [ExtOut], last: $last) {
            edges {
              node {
                id
                boc
                body
                dst
                created_at
                src_transaction { id }
              }
            }
          }
        }
      }
    }
"#;

const GQL_TRANSACTION_BLOCK_ID: &str = r#"
    query($hash: String!) {
      blockchain {
        transaction(hash: $hash) { block_id }
      }
    }
"#;

const GQL_BLOCK_BY_HASH: &str = r#"
    query($hash: String!) {
      blockchain {
        block(hash: $hash) { seq_no }
      }
    }
"#;

const GQL_LATEST_BLOCK: &str = r#"
    query {
      blockchain {
        blocks(last: 1) {
          edges { node { seq_no } }
        }
      }
    }
"#;

#[derive(Debug, Clone)]
pub struct VoucherExtoutMessage {
    pub id: String,
    pub boc: String,
    pub body: String,
    pub dst: String,
    pub created_at: u64,
    pub block_id: Option<String>,
}

pub async fn fetch_extout_voucher_events(
    http: &reqwest::Client,
    endpoint: &str,
    root_pn_address: &Address,
    last: u32,
    with_block_id: bool,
) -> Result<Vec<VoucherExtoutMessage>> {
    let raw = graphql(
        http,
        endpoint,
        serde_json::json!({
            "query": GQL_EXTOUT_MESSAGES,
            "variables": {
                "accountId": root_pn_address.bare(),
                "dappId": root_pn_address.bare(),
                "last": last,
            }
        }),
    )
    .await?;
    let parsed: GqlExtoutResponse =
        serde_json::from_value(raw).map_err(|e| anyhow!("decode RootPN ext-out query: {e}"))?;

    let mut events: Vec<(VoucherExtoutMessage, Option<String>)> = parsed
        .data
        .blockchain
        .account
        .messages
        .edges
        .into_iter()
        .map(|e| e.node)
        .filter(|n| n.dst == VOUCHER_EVENT_DST)
        .map(|n| {
            let tx_id = n.src_transaction.and_then(|t| t.id);
            (
                VoucherExtoutMessage {
                    id: n.id,
                    boc: n.boc.unwrap_or_default(),
                    body: n.body.unwrap_or_default(),
                    dst: n.dst,
                    created_at: n.created_at.unwrap_or(0),
                    block_id: None,
                },
                tx_id,
            )
        })
        .collect();

    if with_block_id {
        for (msg, tx_id) in events.iter_mut() {
            let Some(tx_id) = tx_id.as_deref() else {
                continue;
            };
            msg.block_id = fetch_transaction_block_id(http, endpoint, tx_id).await?;
        }
    }

    Ok(events.into_iter().map(|(m, _)| m).collect())
}

pub async fn wait_for_voucher_event_by_sk_u_commit(
    http: &reqwest::Client,
    endpoint: &str,
    root_pn_address: &Address,
    sk_u_commit_hex: &str,
    timeout: Duration,
) -> Result<VoucherExtoutMessage> {
    let target = parse_u256(sk_u_commit_hex)?;
    let start = Instant::now();

    loop {
        let events =
            fetch_extout_voucher_events(http, endpoint, root_pn_address, 200, true).await?;

        for ev in &events {
            if ev.block_id.is_none() {
                continue;
            }
            let Some(sk_u_commit) = decode_voucher_generated_sk_u_commit(ev)? else {
                continue;
            };
            if sk_u_commit == target {
                return Ok(ev.clone());
            }
        }

        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "timed out waiting for VoucherGenerated event with skUCommit={} within {}s ({} ext-out events scanned)",
                sk_u_commit_hex,
                timeout.as_secs(),
                events.len(),
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub async fn get_block_height_by_id(
    http: &reqwest::Client,
    endpoint: &str,
    block_id: &str,
) -> Result<Option<u64>> {
    let raw = graphql(
        http,
        endpoint,
        serde_json::json!({
            "query": GQL_BLOCK_BY_HASH,
            "variables": { "hash": block_id },
        }),
    )
    .await?;
    let parsed: GqlBlockResponse =
        serde_json::from_value(raw).map_err(|e| anyhow!("decode block-by-hash query: {e}"))?;
    Ok(parsed.data.blockchain.block.map(|b| b.seq_no))
}

pub async fn get_latest_block_height(http: &reqwest::Client, endpoint: &str) -> Result<u64> {
    let raw = graphql(
        http,
        endpoint,
        serde_json::json!({ "query": GQL_LATEST_BLOCK }),
    )
    .await?;
    let parsed: GqlLatestBlockResponse =
        serde_json::from_value(raw).map_err(|e| anyhow!("decode latest-block query: {e}"))?;
    parsed
        .data
        .blockchain
        .blocks
        .edges
        .into_iter()
        .next()
        .map(|e| e.node.seq_no)
        .ok_or_else(|| anyhow!("no blocks returned by GraphQL"))
}

pub async fn wait_for_block_height(
    http: &reqwest::Client,
    endpoint: &str,
    target: u64,
    timeout: Duration,
) -> Result<u64> {
    let start = Instant::now();
    loop {
        match get_latest_block_height(http, endpoint).await {
            Ok(current) if current >= target => return Ok(current),
            Ok(_) | Err(_) => {}
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!("timed out waiting for block height >= {target}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn fetch_transaction_block_id(
    http: &reqwest::Client,
    endpoint: &str,
    tx_id: &str,
) -> Result<Option<String>> {
    let raw = graphql(
        http,
        endpoint,
        serde_json::json!({
            "query": GQL_TRANSACTION_BLOCK_ID,
            "variables": { "hash": tx_id },
        }),
    )
    .await?;
    let parsed: GqlTransactionResponse = serde_json::from_value(raw)
        .map_err(|e| anyhow!("decode transaction block_id query: {e}"))?;
    Ok(parsed.data.blockchain.transaction.and_then(|t| t.block_id))
}

async fn graphql(
    http: &reqwest::Client,
    endpoint: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value> {
    let url = format!("{}/graphql", endpoint.trim_end_matches('/'));
    let raw: serde_json::Value = http
        .post(&url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if let Some(errors) = raw.get("errors") {
        if !errors.is_null() {
            return Err(anyhow!("GraphQL errors: {errors}"));
        }
    }
    Ok(raw)
}

fn decode_voucher_generated_sk_u_commit(
    msg: &VoucherExtoutMessage,
) -> Result<Option<num_bigint::BigUint>> {
    if msg.body.is_empty() {
        return Ok(None);
    }
    use base64::Engine;
    let body_boc = base64::engine::general_purpose::STANDARD
        .decode(&msg.body)
        .map_err(|e| anyhow!("base64 decode VoucherGenerated body: {e}"))?;
    let cell = tvm_types::read_single_root_boc(&body_boc)
        .map_err(|e| anyhow!("read VoucherGenerated body BOC: {e}"))?;
    let body =
        SliceData::load_cell(cell).map_err(|e| anyhow!("load VoucherGenerated body cell: {e}"))?;

    let id =
        tvm_abi::Event::decode_id(body.clone()).map_err(|e| anyhow!("decode event id: {e}"))?;
    let abi = artifacts::root_pn_abi()?;
    let event = abi
        .event_by_id(id)
        .map_err(|e| anyhow!("unknown RootPN event id {id}: {e}"))?;
    if event.name != "VoucherGenerated" {
        return Ok(None);
    }
    let tokens = event
        .decode_input(body, false)
        .map_err(|e| anyhow!("decode VoucherGenerated: {e}"))?;
    for token in tokens {
        if token.name == "skUCommit" {
            if let TokenValue::Uint(u) = token.value {
                return Ok(Some(u.number));
            }
        }
    }
    Err(anyhow!("VoucherGenerated missing skUCommit"))
}

#[derive(Debug, Deserialize)]
struct GqlExtoutResponse {
    data: GqlExtoutData,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutData {
    blockchain: GqlExtoutBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutBlockchain {
    account: GqlExtoutAccount,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutAccount {
    messages: GqlExtoutMessages,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutMessages {
    edges: Vec<GqlExtoutEdge>,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutEdge {
    node: GqlExtoutNode,
}

#[derive(Debug, Deserialize)]
struct GqlExtoutNode {
    id: String,
    boc: Option<String>,
    body: Option<String>,
    dst: String,
    created_at: Option<u64>,
    src_transaction: Option<GqlSrcTransaction>,
}

#[derive(Debug, Deserialize)]
struct GqlSrcTransaction {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GqlTransactionResponse {
    data: GqlTransactionData,
}

#[derive(Debug, Deserialize)]
struct GqlTransactionData {
    blockchain: GqlTransactionBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlTransactionBlockchain {
    transaction: Option<GqlTransactionFields>,
}

#[derive(Debug, Deserialize)]
struct GqlTransactionFields {
    block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GqlBlockResponse {
    data: GqlBlockData,
}

#[derive(Debug, Deserialize)]
struct GqlBlockData {
    blockchain: GqlBlockBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlBlockBlockchain {
    block: Option<GqlBlockFields>,
}

#[derive(Debug, Deserialize)]
struct GqlBlockFields {
    seq_no: u64,
}

#[derive(Debug, Deserialize)]
struct GqlLatestBlockResponse {
    data: GqlLatestBlockData,
}

#[derive(Debug, Deserialize)]
struct GqlLatestBlockData {
    blockchain: GqlLatestBlockBlockchain,
}

#[derive(Debug, Deserialize)]
struct GqlLatestBlockBlockchain {
    blocks: GqlLatestBlocks,
}

#[derive(Debug, Deserialize)]
struct GqlLatestBlocks {
    edges: Vec<GqlLatestBlockEdge>,
}

#[derive(Debug, Deserialize)]
struct GqlLatestBlockEdge {
    node: GqlBlockFields,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voucher_event_dst_is_voucher_generated_slot_135() {
        assert!(VOUCHER_EVENT_DST.ends_with("87"));
        assert_eq!(
            u128::from_str_radix(&VOUCHER_EVENT_DST[1..], 16).unwrap(),
            135
        );
    }
}
