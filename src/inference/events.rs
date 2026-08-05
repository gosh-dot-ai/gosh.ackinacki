// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Typed inference-market events, decoded from ext-out message bodies.
//!
//! Three contract families emit the market's event stream:
//! - the **order book** (`InferenceOrderBook`) — placed / cancelled / filled /
//!   executed / refunded / subscriptions: the market feed itself;
//! - each trader's **PrivateNote** — note-side confirmations (`Note*` variants)
//!   and private transfers;
//! - **RootPN** — note lifecycle (vouchers, note deploys).
//!
//! [`decode_event_body_b64`] tries all three ABIs (event ids are
//! signature-derived, so they cannot collide) and returns `Ok(None)` for a
//! foreign message — the shape [`crate::airegistry::getter::AccountReader::read_events_with`]
//! and the block-stream filter both want. Unmapped-but-recognised events fall
//! back to [`InferenceEvent::Other`] so nothing is silently dropped.
//!
//! Prices (`uint256` fields) are carried as **decimal strings** to stay
//! lossless; tick counts / amounts are `u128` per the ABI.

use anyhow::{anyhow, Result};
use serde::Serialize;
use tvm_abi::{Contract, Token, TokenValue};
use tvm_types::SliceData;

use crate::inference::abi;

/// A decoded inference-market event. `Note*` variants are emitted by a trader's
/// PrivateNote; the rest by the order book (or RootPN for note lifecycle).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InferenceEvent {
    // ---- order book (the market feed) ----
    /// A new resting order entered the book.
    OrderPlaced {
        order_id: u128,
        is_buy: bool,
        /// Price per tick (decimal string).
        price: String,
        ticks: u128,
        note: String,
        token_contract: String,
        deadline: u64,
    },
    /// A resting order was cancelled; `refunded` escrow returned to `note`.
    OrderCancelled {
        order_id: u128,
        refunded: u128,
        note: String,
    },
    /// A trade: maker/taker matched for `ticks` at `clearing_price`.
    Filled {
        maker_id: u128,
        taker_id: u128,
        ticks: u128,
        clearing_price: String,
        seller_token_contract: String,
        buyer_note: String,
        seller_note: String,
    },
    /// Inference actually executed (consumption of a filled order).
    Executed {
        ticks: u128,
        clearing_price: String,
        cost: u128,
    },
    /// Escrow returned outside a cancel (e.g. expiry).
    Refunded { note: String, amount: u128 },
    /// A recurring (subscription) buy order was placed.
    SubscriptionPlaced {
        order_id: u128,
        buyer_note: String,
        max_price: u128,
        ticks: u128,
        cycle_budget: u128,
        auto_renew: bool,
    },
    /// A subscription cycle lapsed unspent; its budget entered the forfeit pool.
    CycleForfeited {
        order_id: u128,
        cycle: u8,
        forfeited: u128,
        funded_ticks: u128,
    },
    /// A seller claimed its share of a forfeited cycle pool.
    ForfeitClaimed {
        order_id: u128,
        cycle: u8,
        seller_note: String,
        amount: u128,
    },
    /// A per-model order book was deployed (by `note`).
    BookDeployed {
        note: String,
        model_hash: String,
        model_name: String,
    },

    // ---- note-side confirmations (emitted by a trader's PrivateNote) ----
    /// The note's inference order landed in a book.
    NoteInferenceOrderPlaced {
        order_book: String,
        token_contract: String,
        order_id: u128,
        is_buy: bool,
        price: String,
        ticks: u128,
    },
    /// The note's inference order (partially) filled.
    NoteInferenceFilled {
        order_book: String,
        token_contract: String,
        order_id: u128,
        ticks: u128,
        clearing_price: String,
        is_buy: bool,
    },
    /// The note submitted a (prediction-market) order.
    NoteOrderSubmitted {
        client_order_id: u128,
        outcome_id: u32,
        is_buy: bool,
        price: String,
        amount: u128,
        event_id: String,
        token_type: u32,
    },
    NoteOrderPlaced {
        order_book: String,
        order_id: u128,
        client_order_id: u128,
        outcome_id: u32,
        is_buy: bool,
        price: String,
        amount: u128,
    },
    NoteOrderFilled {
        order_book: String,
        order_id: u128,
        outcome_id: u32,
        filled_amount: u128,
        clearing_price: String,
        is_buy: bool,
        fee_amount: u128,
        is_rebate: bool,
        is_final: bool,
    },
    NoteOrderCancelled {
        order_book: String,
        order_id: u128,
        outcome_id: u32,
        is_buy: bool,
        return_amount: u128,
    },
    NoteOrderRejected {
        order_book: String,
        event_id: String,
        client_order_id: u128,
        outcome_id: u32,
        is_buy: bool,
        price: String,
        amount: u128,
    },
    /// The note sent a private transfer out.
    NoteTransferInitiated {
        dest: String,
        token_type: u32,
        amount: u128,
    },
    /// The note received a private transfer.
    NoteTransferReceived {
        from: String,
        token_type: u32,
        amount: u128,
    },

    // ---- RootPN (note lifecycle) ----
    /// A deposit voucher was generated (`skUCommit` binds it to its owner).
    VoucherGenerated {
        sk_u_commit: String,
        voucher_nominal: String,
        token_type: u32,
    },
    /// A PrivateNote was deployed and funded.
    NoteDeployed {
        deposit_identifier_hash: String,
        note: String,
        initial_balance: u128,
    },

    /// A recognised event of these contracts we don't map into a typed variant
    /// (e.g. prediction-market stakes) — kept so nothing is dropped.
    Other { name: String },
}

/// The three loaded inference-market ABIs, ready for repeated decoding. Load
/// once (e.g. per subscription) with [`InferenceAbis::load`].
pub struct InferenceAbis {
    order_book: Contract,
    note: Contract,
    root_pn: Contract,
}

impl InferenceAbis {
    pub fn load() -> Result<Self> {
        Ok(Self {
            order_book: abi::order_book_abi()?,
            note: abi::note_abi()?,
            root_pn: abi::root_pn_abi()?,
        })
    }

    fn contracts(&self) -> [&Contract; 3] {
        [&self.order_book, &self.note, &self.root_pn]
    }
}

/// Decode an ext-out event **body** (base64 BOC, the GraphQL `body` field) into
/// a typed [`InferenceEvent`]. `Ok(None)` when the body is not an event of the
/// inference-market contract family (a foreign message to skip).
pub fn decode_event_body_b64(
    abis: &InferenceAbis,
    body_b64: &str,
) -> Result<Option<InferenceEvent>> {
    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD
        .decode(body_b64)
        .map_err(|e| anyhow!("base64 decode event body: {e}"))?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow!("read body boc: {e}"))?;
    let body = SliceData::load_cell(cell).map_err(|e| anyhow!("load body cell: {e}"))?;
    decode_event_body(abis, body)
}

/// Like [`decode_event_body_b64`] but from an already-loaded body slice (the
/// shape the block-stream filter's [`crate::filter::engine::MatchedMessage`]
/// carries).
pub fn decode_event_body(abis: &InferenceAbis, body: SliceData) -> Result<Option<InferenceEvent>> {
    let Ok(id) = tvm_abi::Event::decode_id(body.clone()) else {
        return Ok(None);
    };
    for contract in abis.contracts() {
        if let Ok(event) = contract.event_by_id(id) {
            let tokens = event
                .decode_input(body, false)
                .map_err(|e| anyhow!("decode event {}: {e}", event.name))?;
            return map_event(&event.name, &tokens).map(Some);
        }
    }
    Ok(None)
}

fn map_event(name: &str, t: &[Token]) -> Result<InferenceEvent> {
    Ok(match name {
        // ---- order book ----
        "InferenceOrderPlaced" => InferenceEvent::OrderPlaced {
            order_id: uint(t, "orderId")?,
            is_buy: boolean(t, "isBuy")?,
            price: uint_dec(t, "price")?,
            ticks: uint(t, "ticks")?,
            note: addr(t, "note")?,
            token_contract: addr(t, "tokenContract")?,
            deadline: uint(t, "deadline")? as u64,
        },
        "InferenceOrderCancelled" => InferenceEvent::OrderCancelled {
            order_id: uint(t, "orderId")?,
            refunded: uint(t, "refunded")?,
            note: addr(t, "note")?,
        },
        "InferenceFilled" => InferenceEvent::Filled {
            maker_id: uint(t, "makerId")?,
            taker_id: uint(t, "takerId")?,
            ticks: uint(t, "ticks")?,
            clearing_price: uint_dec(t, "clearingPrice")?,
            seller_token_contract: addr(t, "sellerTC")?,
            buyer_note: addr(t, "buyerNote")?,
            seller_note: addr(t, "sellerNote")?,
        },
        "InferenceExecuted" => InferenceEvent::Executed {
            ticks: uint(t, "ticks")?,
            clearing_price: uint_dec(t, "clearingPrice")?,
            cost: uint(t, "cost")?,
        },
        "InferenceRefunded" => InferenceEvent::Refunded {
            note: addr(t, "note")?,
            amount: uint(t, "amount")?,
        },
        "InferenceSubscriptionPlaced" => InferenceEvent::SubscriptionPlaced {
            order_id: uint(t, "orderId")?,
            buyer_note: addr(t, "buyerNote")?,
            max_price: uint(t, "maxPrice")?,
            ticks: uint(t, "ticks")?,
            cycle_budget: uint(t, "cycleBudget")?,
            auto_renew: boolean(t, "autoRenew")?,
        },
        "InferenceCycleForfeited" => InferenceEvent::CycleForfeited {
            order_id: uint(t, "orderId")?,
            cycle: uint(t, "cycle")? as u8,
            forfeited: uint(t, "forfeited")?,
            funded_ticks: uint(t, "fundedTicks")?,
        },
        "InferenceForfeitClaimed" => InferenceEvent::ForfeitClaimed {
            order_id: uint(t, "orderId")?,
            cycle: uint(t, "cycle")? as u8,
            seller_note: addr(t, "sellerNote")?,
            amount: uint(t, "amount")?,
        },
        "InferenceOrderBookDeployed" => InferenceEvent::BookDeployed {
            note: addr(t, "note")?,
            model_hash: uint_dec(t, "modelHash")?,
            model_name: string(t, "modelName")?,
        },

        // ---- note-side ----
        "InferenceOrderPlacedConfirmed" => InferenceEvent::NoteInferenceOrderPlaced {
            order_book: addr(t, "orderBook")?,
            token_contract: addr(t, "tokenContract")?,
            order_id: uint(t, "orderId")?,
            is_buy: boolean(t, "isBuy")?,
            price: uint_dec(t, "price")?,
            ticks: uint(t, "ticks")?,
        },
        "InferenceFilledConfirmed" => InferenceEvent::NoteInferenceFilled {
            order_book: addr(t, "orderBook")?,
            token_contract: addr(t, "tokenContract")?,
            order_id: uint(t, "orderId")?,
            ticks: uint(t, "ticks")?,
            clearing_price: uint_dec(t, "clearingPrice")?,
            is_buy: boolean(t, "isBuy")?,
        },
        "OrderSubmitted" => InferenceEvent::NoteOrderSubmitted {
            client_order_id: uint(t, "clientOrderId")?,
            outcome_id: uint(t, "outcomeId")? as u32,
            is_buy: boolean(t, "isBuy")?,
            price: uint_dec(t, "price")?,
            amount: uint(t, "amount")?,
            event_id: uint_dec(t, "eventId")?,
            token_type: uint(t, "tokenType")? as u32,
        },
        "OrderPlacedConfirmed" => InferenceEvent::NoteOrderPlaced {
            order_book: addr(t, "orderBook")?,
            order_id: uint(t, "orderId")?,
            client_order_id: uint(t, "clientOrderId")?,
            outcome_id: uint(t, "outcomeId")? as u32,
            is_buy: boolean(t, "isBuy")?,
            price: uint_dec(t, "price")?,
            amount: uint(t, "amount")?,
        },
        "OrderFilledConfirmed" => InferenceEvent::NoteOrderFilled {
            order_book: addr(t, "orderBook")?,
            order_id: uint(t, "orderId")?,
            outcome_id: uint(t, "outcomeId")? as u32,
            filled_amount: uint(t, "filledAmount")?,
            clearing_price: uint_dec(t, "clearingPrice")?,
            is_buy: boolean(t, "isBuy")?,
            fee_amount: uint(t, "feeAmount")?,
            is_rebate: boolean(t, "isRebate")?,
            is_final: boolean(t, "isFinal")?,
        },
        "OrderCancelledConfirmed" => InferenceEvent::NoteOrderCancelled {
            order_book: addr(t, "orderBook")?,
            order_id: uint(t, "orderId")?,
            outcome_id: uint(t, "outcomeId")? as u32,
            is_buy: boolean(t, "isBuy")?,
            return_amount: uint(t, "returnAmount")?,
        },
        "OrderPlaceRejected" => InferenceEvent::NoteOrderRejected {
            order_book: addr(t, "orderBook")?,
            event_id: uint_dec(t, "eventId")?,
            client_order_id: uint(t, "clientOrderId")?,
            outcome_id: uint(t, "outcomeId")? as u32,
            is_buy: boolean(t, "isBuy")?,
            price: uint_dec(t, "price")?,
            amount: uint(t, "amount")?,
        },
        "TransferInitiated" => InferenceEvent::NoteTransferInitiated {
            dest: addr(t, "dest")?,
            token_type: uint(t, "tokenType")? as u32,
            amount: uint(t, "amount")?,
        },
        "TransferReceived" => InferenceEvent::NoteTransferReceived {
            from: addr(t, "from")?,
            token_type: uint(t, "tokenType")? as u32,
            amount: uint(t, "amount")?,
        },

        // ---- RootPN ----
        "VoucherGenerated" => InferenceEvent::VoucherGenerated {
            sk_u_commit: uint_dec(t, "skUCommit")?,
            voucher_nominal: uint_dec(t, "voucherNominal")?,
            token_type: uint(t, "tokenType")? as u32,
        },
        "PrivateNoteDeployed" => InferenceEvent::NoteDeployed {
            deposit_identifier_hash: uint_dec(t, "depositIdentifierHash")?,
            note: addr(t, "noteAddress")?,
            initial_balance: uint(t, "initialBalance")?,
        },

        other => InferenceEvent::Other {
            name: other.to_string(),
        },
    })
}

// ---- token extraction helpers ----

fn find<'a>(tokens: &'a [Token], name: &str) -> Result<&'a TokenValue> {
    tokens
        .iter()
        .find(|t| t.name == name)
        .map(|t| &t.value)
        .ok_or_else(|| anyhow!("event missing field '{name}'"))
}

fn addr(tokens: &[Token], name: &str) -> Result<String> {
    match find(tokens, name)? {
        TokenValue::Address(a) => Ok(a.to_string()),
        v => Err(anyhow!("event field '{name}' is not an address: {v:?}")),
    }
}

/// Unsigned field as `u128` (every amount/ticks/id field in these ABIs is
/// declared ≤ 128 bits).
fn uint(tokens: &[Token], name: &str) -> Result<u128> {
    uint_dec(tokens, name)?
        .parse::<u128>()
        .map_err(|_| anyhow!("event field '{name}' does not fit u128"))
}

/// Unsigned field as a lossless decimal string (for `uint256` prices/hashes).
fn uint_dec(tokens: &[Token], name: &str) -> Result<String> {
    match find(tokens, name)? {
        TokenValue::Uint(u) => Ok(u.number.to_string()),
        v => Err(anyhow!("event field '{name}' is not a uint: {v:?}")),
    }
}

fn boolean(tokens: &[Token], name: &str) -> Result<bool> {
    match find(tokens, name)? {
        TokenValue::Bool(b) => Ok(*b),
        v => Err(anyhow!("event field '{name}' is not a bool: {v:?}")),
    }
}

fn string(tokens: &[Token], name: &str) -> Result<String> {
    match find(tokens, name)? {
        TokenValue::String(s) => Ok(s.clone()),
        v => Err(anyhow!("event field '{name}' is not a string: {v:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abis_load_and_ids_do_not_collide() {
        let abis = InferenceAbis::load().unwrap();
        let mut ids = std::collections::HashMap::new();
        for c in abis.contracts() {
            for e in c.events().values() {
                if let Some(prev) = ids.insert(e.get_function_id(), e.name.clone()) {
                    assert_eq!(
                        prev, e.name,
                        "event id collision across ABIs: {prev} vs {}",
                        e.name
                    );
                }
            }
        }
        // The 9 order-book events must all be known.
        for name in [
            "InferenceOrderPlaced",
            "InferenceOrderCancelled",
            "InferenceFilled",
            "InferenceExecuted",
            "InferenceRefunded",
            "InferenceSubscriptionPlaced",
            "InferenceCycleForfeited",
            "InferenceForfeitClaimed",
            "InferenceOrderBookDeployed",
        ] {
            assert!(
                ids.values().any(|n| n == name),
                "order-book event {name} missing from loaded ABIs"
            );
        }
    }

    #[test]
    fn non_event_body_decodes_to_none() {
        let abis = InferenceAbis::load().unwrap();
        // A body whose leading u32 matches no known event id.
        let body = SliceData::new(vec![0xde, 0xad, 0xbe, 0xef, 0x80]);
        assert_eq!(decode_event_body(&abis, body).unwrap(), None);
    }

    #[test]
    fn map_event_unknown_name_is_other() {
        let ev = map_event("SomeStakeEvent", &[]).unwrap();
        assert_eq!(
            ev,
            InferenceEvent::Other {
                name: "SomeStakeEvent".into()
            }
        );
    }

    #[test]
    fn inference_event_serializes_with_type_tag() {
        let ev = InferenceEvent::OrderCancelled {
            order_id: 7,
            refunded: 100,
            note: "0:abc".into(),
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["type"], "order_cancelled");
        assert_eq!(v["order_id"], 7);
    }
}
