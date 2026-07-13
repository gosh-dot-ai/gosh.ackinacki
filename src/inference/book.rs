// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! The order-book view: reconstruct **all open orders** of an
//! `InferenceOrderBook` as one consistent snapshot.
//!
//! The account BOC is fetched **once**, then every getter (`getParams`,
//! `getStats`, `getBestBidAsk`, `getWeeklyMedianPrice`, `getModelName`, and
//! `getOrder(id)` for each candidate id) runs **locally** over that same BOC —
//! one network read regardless of book size, and a snapshot that cannot tear
//! across a concurrent fill. Order ids are dense (`1..nextOrderId` as assigned
//! by the contract); ids whose order is gone (filled/cancelled) simply fail the
//! getter and are skipped, and the scan stops early once `orderCount` live
//! orders have been found.

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::airegistry::getter::{AccountOrigin, AccountReader};
use crate::airegistry::run::GetterRunner;
use crate::config::AiRegistryConfig;
use crate::inference::abi::INFERENCE_ORDER_BOOK_ABI_JSON;

/// One live (resting) order in the book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOrder {
    pub order_id: u128,
    pub is_buy: bool,
    /// Price per tick.
    pub price: u128,
    /// Remaining size in ticks.
    pub ticks: u128,
    /// Escrow currently locked behind the order.
    pub escrow: u128,
    /// The PrivateNote that owns the order.
    pub note: String,
    /// Seller's SPC TokenContract (zero address on plain buys).
    pub token_contract: String,
    /// Unix expiry (0 = none).
    pub deadline: u64,
    pub flags: u8,
    /// Unix time the order was placed.
    pub placed_at: u64,
}

/// Aggregate counters from `getStats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BookStats {
    pub next_order_id: u128,
    pub order_count: u128,
    pub executed_notional: u128,
    pub executed_ticks: u128,
}

/// A consistent snapshot of one model's order book.
#[derive(Debug, Clone, Serialize)]
pub struct OrderBookSnapshot {
    /// The order book account (`0:<hex>`).
    pub address: String,
    /// The model this book trades (decimal uint256).
    pub model_hash: String,
    pub model_name: String,
    pub platform_fee_bps: u16,
    /// Best bid / best ask (price per tick), when present.
    pub best_bid: Option<u128>,
    pub best_ask: Option<u128>,
    /// Volume-weighted 7-day median price. `None` until the book has enough
    /// traded volume — a fresh/thin book has no median (the on-chain getter
    /// reverts `ERR_NO_LIQUIDITY`), which is not a snapshot failure.
    pub weekly_median_price: Option<u128>,
    pub stats: BookStats,
    /// Open buy orders, best (highest price) first.
    pub bids: Vec<OpenOrder>,
    /// Open sell orders, best (lowest price) first.
    pub asks: Vec<OpenOrder>,
    /// True if the id scan hit `max_scan` before finding all live orders — the
    /// book is larger than the scan budget and `bids`/`asks` are incomplete.
    pub truncated: bool,
}

/// The all-zero (system) DApp id. Contracts deployed by an internal message
/// inherit their deployer's DApp — an order book deployed by a PrivateNote
/// (whose lineage starts at RootPN) lives in this DApp, not under its own id.
pub const SYSTEM_DAPP_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Fetch a full order-book snapshot. `Ok(None)` when the account does not exist
/// or is not active (book not deployed). The caller states the book's
/// [`AccountOrigin`] (its DApp routing — note-deployed books live in the system
/// DApp; see [`SYSTEM_DAPP_ID`]). `max_scan` caps how many order ids are probed
/// (defense against a pathological `nextOrderId`); pass e.g. `10_000`.
pub async fn fetch_order_book(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    address: &str,
    origin: &AccountOrigin,
    max_scan: u128,
) -> Result<Option<OrderBookSnapshot>> {
    let snapshot = match reader.fetch(cfg, address, origin).await? {
        Some(s) if s.is_active() => s,
        _ => return Ok(None),
    };
    let boc = snapshot
        .boc
        .as_deref()
        .ok_or_else(|| anyhow!("order book {address} is active but returned no BOC"))?;
    let addr_wc = format!("0:{}", snapshot.account_id);
    let abi = INFERENCE_ORDER_BOOK_ABI_JSON;

    let run = |method: &'static str, input: Value| {
        let addr_wc = addr_wc.clone();
        async move { runner.run_getter(abi, &addr_wc, boc, method, input).await }
    };

    let params = run("getParams", json!({})).await?;
    let name = run("getModelName", json!({})).await?;
    let stats_v = run("getStats", json!({})).await?;
    let bba = run("getBestBidAsk", json!({})).await?;
    // Optional: reverts ERR_NO_LIQUIDITY (334) until the book has traded volume.
    let median = run("getWeeklyMedianPrice", json!({})).await.ok();

    let stats = BookStats {
        next_order_id: field_u128(&stats_v, "nextOrderId")?,
        order_count: field_u128(&stats_v, "orderCount")?,
        executed_notional: field_u128(&stats_v, "executedNotional")?,
        executed_ticks: field_u128(&stats_v, "executedTicks")?,
    };

    // Scan candidate ids until all live orders are found (or the budget ends).
    let mut bids = Vec::new();
    let mut asks = Vec::new();
    let mut found: u128 = 0;
    let mut probed: u128 = 0;
    let mut id: u128 = 1;
    while found < stats.order_count && id <= stats.next_order_id && probed < max_scan {
        probed += 1;
        if let Ok(o) = run("getOrder", json!({ "id": id.to_string() })).await {
            // A live order always carries its owning note; a zero/absent note
            // means the slot exists but is not a live order.
            let note = field_str(&o, "note").unwrap_or_default();
            if !note.is_empty() && !note.ends_with(&"0".repeat(64)) {
                let order = OpenOrder {
                    order_id: id,
                    is_buy: field_bool(&o, "isBuy")?,
                    price: field_u128(&o, "price")?,
                    ticks: field_u128(&o, "amount")?,
                    escrow: field_u128(&o, "escrow")?,
                    note,
                    token_contract: field_str(&o, "tokenContract").unwrap_or_default(),
                    deadline: field_u128(&o, "deadline")? as u64,
                    flags: field_u128(&o, "flags")? as u8,
                    placed_at: field_u128(&o, "ts")? as u64,
                };
                found += 1;
                if order.is_buy {
                    bids.push(order);
                } else {
                    asks.push(order);
                }
            }
        }
        id += 1;
    }
    let truncated = found < stats.order_count;
    // Price-time priority: best first (bids: highest price; asks: lowest), ties
    // by placement time.
    bids.sort_by(|a, b| b.price.cmp(&a.price).then(a.placed_at.cmp(&b.placed_at)));
    asks.sort_by(|a, b| a.price.cmp(&b.price).then(a.placed_at.cmp(&b.placed_at)));

    let has_bid = field_bool(&bba, "hasBid")?;
    let has_ask = field_bool(&bba, "hasAsk")?;
    Ok(Some(OrderBookSnapshot {
        address: addr_wc,
        model_hash: field_dec(&params, "modelHash")?,
        model_name: field_str(&name, "value0").unwrap_or_default(),
        platform_fee_bps: field_u128(&params, "platformFeeBps")? as u16,
        best_bid: if has_bid {
            Some(field_u128(&bba, "bid")?)
        } else {
            None
        },
        best_ask: if has_ask {
            Some(field_u128(&bba, "ask")?)
        } else {
            None
        },
        weekly_median_price: median.as_ref().and_then(|m| field_u128(m, "value0").ok()),
        stats,
        bids,
        asks,
        truncated,
    }))
}

// ---- getter-output field parsing (uints arrive as decimal or 0x-hex strings) ----

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name)
        .ok_or_else(|| anyhow!("getter output missing field '{name}': {v}"))
}

fn field_u128(v: &Value, name: &str) -> Result<u128> {
    let f = field(v, name)?;
    match f {
        Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u128::from_str_radix(hex, 16).map_err(|_| anyhow!("field '{name}' bad hex: {s}"))
            } else {
                s.parse()
                    .map_err(|_| anyhow!("field '{name}' bad uint: {s}"))
            }
        }
        Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| anyhow!("field '{name}' is not an unsigned number")),
        _ => Err(anyhow!("field '{name}' is not a uint: {f}")),
    }
}

/// Lossless decimal string for uint256-sized fields (hashes).
fn field_dec(v: &Value, name: &str) -> Result<String> {
    let f = field(v, name)?;
    match f {
        Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                // Decode via big-endian bytes → decimal without external deps.
                let mut digits: Vec<u8> = vec![0];
                for c in hex.chars() {
                    let mut carry = c
                        .to_digit(16)
                        .ok_or_else(|| anyhow!("bad hex in '{name}'"))?;
                    for dig in digits.iter_mut() {
                        let val = (*dig as u32) * 16 + carry;
                        *dig = (val % 10) as u8;
                        carry = val / 10;
                    }
                    while carry > 0 {
                        digits.push((carry % 10) as u8);
                        carry /= 10;
                    }
                }
                Ok(digits
                    .iter()
                    .rev()
                    .map(|d| char::from(b'0' + d))
                    .collect::<String>())
            } else {
                Ok(s.to_string())
            }
        }
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(anyhow!("field '{name}' is not a uint: {f}")),
    }
}

fn field_bool(v: &Value, name: &str) -> Result<bool> {
    field(v, name)?
        .as_bool()
        .ok_or_else(|| anyhow!("field '{name}' is not a bool"))
}

fn field_str(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(|s| s.as_str()).map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_u128_accepts_dec_hex_and_number() {
        let v = json!({ "a": "42", "b": "0x2a", "c": 42 });
        assert_eq!(field_u128(&v, "a").unwrap(), 42);
        assert_eq!(field_u128(&v, "b").unwrap(), 42);
        assert_eq!(field_u128(&v, "c").unwrap(), 42);
        assert!(field_u128(&v, "missing").is_err());
    }

    #[test]
    fn field_dec_converts_hex_losslessly() {
        let v = json!({ "h": "0xff", "d": "123", "big": format!("0x{}", "f".repeat(64)) });
        assert_eq!(field_dec(&v, "h").unwrap(), "255");
        assert_eq!(field_dec(&v, "d").unwrap(), "123");
        // 2^256 - 1
        assert_eq!(
            field_dec(&v, "big").unwrap(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn book_sides_sort_price_time() {
        let mk = |id: u128, is_buy: bool, price: u128, ts: u64| OpenOrder {
            order_id: id,
            is_buy,
            price,
            ticks: 1,
            escrow: 0,
            note: "0:aa".into(),
            token_contract: String::new(),
            deadline: 0,
            flags: 0,
            placed_at: ts,
        };
        let mut bids = [mk(1, true, 5, 20), mk(2, true, 9, 10), mk(3, true, 9, 5)];
        let mut asks = [mk(4, false, 7, 9), mk(5, false, 3, 30), mk(6, false, 3, 2)];
        bids.sort_by(|a, b| b.price.cmp(&a.price).then(a.placed_at.cmp(&b.placed_at)));
        asks.sort_by(|a, b| a.price.cmp(&b.price).then(a.placed_at.cmp(&b.placed_at)));
        assert_eq!(
            bids.iter().map(|o| o.order_id).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "bids: highest price first, earlier ts breaks the tie"
        );
        assert_eq!(
            asks.iter().map(|o| o.order_id).collect::<Vec<_>>(),
            vec![6, 5, 4],
            "asks: lowest price first, earlier ts breaks the tie"
        );
    }
}
