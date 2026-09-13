// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Decode airegistry events from ext-out message bodies.
//!
//! The contracts emit directed events (`address.makeAddrExtern(<Emit>, 256)` +
//! `emit`). An event message body is `event_id:u32 ++ packed-params`. We track
//! these via the GraphQL `events` query (Phase 1) — never getter polling — and
//! decode the body with the contract ABI: `event_id` → `event_by_id` →
//! `decode_input`.

use anyhow::{anyhow, Result};
use tvm_abi::{Contract, Token, TokenValue};
use tvm_types::SliceData;

/// A decoded airegistry event (the variants the wrapper acts on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiRegistryEvent {
    ContractDeployed {
        self_addr: String,
    },
    RootRegistered {
        root: String,
    },
    ManifestRegistered {
        manifest: String,
    },
    TokenContractRegistered {
        token: String,
    },
    ManifestUpdated {
        self_addr: String,
        chunk_idx: u32,
    },
    TokensPurchased {
        buyer: String,
        amount: u128,
        fee: u128,
    },
    FeeBurned {
        amount: u128,
    },
    TokensConsumed {
        buyer: String,
        amount: u128,
        sessions: u16,
    },
    TokensReplenished {
        amount: u128,
        available: u128,
    },
    ShellWithdrawn {
        recipient: String,
        amount: u128,
    },
    /// Buyer hard-cancelled the reservation: `refunded` ECC[2] SHELL returned,
    /// `carried_seller_owed` left for the seller to withdraw.
    ReservationCancelled {
        buyer: String,
        refunded: u128,
        carried_seller_owed: u128,
    },
    /// Seller pulled tokens off the sale shelf.
    AvailableReduced {
        amount: u128,
        available: u128,
    },
    ContractDestroyed {
        self_addr: String,
    },
    /// A recognised event whose payload we don't map into a typed variant.
    Other {
        name: String,
    },
}

/// Decode an event message body against a contract ABI.
pub fn decode_event_body(contract: &Contract, body: SliceData) -> Result<AiRegistryEvent> {
    let id =
        tvm_abi::Event::decode_id(body.clone()).map_err(|e| anyhow!("decode event id: {e}"))?;
    let event = contract
        .event_by_id(id)
        .map_err(|e| anyhow!("unknown event id {id}: {e}"))?;
    let tokens = event
        .decode_input(body, false)
        .map_err(|e| anyhow!("decode event {}: {e}", event.name))?;
    map_event(&event.name, &tokens)
}

/// Decode an event **body** cell (base64 BOC) into an airegistry event. This is
/// the shape the GraphQL `blockchain.account.messages` query returns in the
/// `body` field for an ext-out (msg_type 2) event message.
pub fn decode_event_body_b64(contract: &Contract, body_b64: &str) -> Result<AiRegistryEvent> {
    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD
        .decode(body_b64)
        .map_err(|e| anyhow!("base64 decode event body: {e}"))?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow!("read body boc: {e}"))?;
    let body = SliceData::load_cell(cell).map_err(|e| anyhow!("load body cell: {e}"))?;
    decode_event_body(contract, body)
}

/// Decode an ext-out message (BOC, base64) into an airegistry event.
pub fn decode_ext_out_event_boc(contract: &Contract, boc_b64: &str) -> Result<AiRegistryEvent> {
    use base64::Engine;
    use tvm_block::{Deserializable, Message};
    let boc = base64::engine::general_purpose::STANDARD
        .decode(boc_b64)
        .map_err(|e| anyhow!("base64 decode ext-out: {e}"))?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow!("read boc: {e}"))?;
    let msg = Message::construct_from_cell(cell).map_err(|e| anyhow!("parse message: {e}"))?;
    let body = msg
        .body()
        .ok_or_else(|| anyhow!("ext-out message has no body"))?;
    decode_event_body(contract, body)
}

fn tok_addr(tokens: &[Token], name: &str) -> Result<String> {
    for t in tokens {
        if t.name == name {
            if let TokenValue::Address(a) = &t.value {
                return Ok(a.to_string());
            }
        }
    }
    Err(anyhow!("event missing address field '{name}'"))
}

fn tok_uint(tokens: &[Token], name: &str) -> Result<u128> {
    for t in tokens {
        if t.name == name {
            if let TokenValue::Uint(u) = &t.value {
                // tvm_abi Uint stores a BigUint; fits our u128 fields by ABI.
                return u
                    .number
                    .to_string()
                    .parse::<u128>()
                    .map_err(|_| anyhow!("event field '{name}' does not fit u128"));
            }
        }
    }
    Err(anyhow!("event missing uint field '{name}'"))
}

fn map_event(name: &str, tokens: &[Token]) -> Result<AiRegistryEvent> {
    Ok(match name {
        "ContractDeployed" => AiRegistryEvent::ContractDeployed {
            self_addr: tok_addr(tokens, "self")?,
        },
        "RootRegistered" => AiRegistryEvent::RootRegistered {
            root: tok_addr(tokens, "rootAddress").or_else(|_| tok_addr(tokens, "root"))?,
        },
        "ManifestRegistered" => AiRegistryEvent::ManifestRegistered {
            manifest: tok_addr(tokens, "manifestAddress")
                .or_else(|_| tok_addr(tokens, "manifest"))?,
        },
        "TokenContractRegistered" => AiRegistryEvent::TokenContractRegistered {
            token: tok_addr(tokens, "tokenContractAddress")
                .or_else(|_| tok_addr(tokens, "token"))?,
        },
        "ManifestUpdated" => AiRegistryEvent::ManifestUpdated {
            self_addr: tok_addr(tokens, "self")?,
            chunk_idx: tok_uint(tokens, "chunkIdx").unwrap_or(0) as u32,
        },
        "TokensPurchased" => AiRegistryEvent::TokensPurchased {
            buyer: tok_addr(tokens, "buyer")?,
            amount: tok_uint(tokens, "amount")?,
            fee: tok_uint(tokens, "fee")?,
        },
        "FeeBurned" => AiRegistryEvent::FeeBurned {
            amount: tok_uint(tokens, "amount")?,
        },
        "TokensConsumed" => AiRegistryEvent::TokensConsumed {
            buyer: tok_addr(tokens, "buyer")?,
            amount: tok_uint(tokens, "amount")?,
            sessions: tok_uint(tokens, "sessions")? as u16,
        },
        "TokensReplenished" => AiRegistryEvent::TokensReplenished {
            amount: tok_uint(tokens, "amount")?,
            available: tok_uint(tokens, "availableTokens")
                .or_else(|_| tok_uint(tokens, "available"))?,
        },
        "ShellWithdrawn" => AiRegistryEvent::ShellWithdrawn {
            recipient: tok_addr(tokens, "recipient")?,
            amount: tok_uint(tokens, "amount")?,
        },
        "ReservationCancelled" => AiRegistryEvent::ReservationCancelled {
            buyer: tok_addr(tokens, "buyer")?,
            refunded: tok_uint(tokens, "refundedToBuyer")
                .or_else(|_| tok_uint(tokens, "refunded"))?,
            carried_seller_owed: tok_uint(tokens, "carriedSellerOwed")
                .or_else(|_| tok_uint(tokens, "carried_seller_owed"))
                .unwrap_or(0),
        },
        "AvailableReduced" => AiRegistryEvent::AvailableReduced {
            amount: tok_uint(tokens, "amount")?,
            available: tok_uint(tokens, "availableTokens")
                .or_else(|_| tok_uint(tokens, "available"))?,
        },
        "ContractDestroyed" => AiRegistryEvent::ContractDestroyed {
            self_addr: tok_addr(tokens, "self")?,
        },
        other => AiRegistryEvent::Other {
            name: other.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airegistry::abi::Contract as AirContract;

    /// Encode an event body exactly the way the contract emits it:
    /// `event_id:u32 ++ packed-params`. Faithful because `decode_input` reads
    /// `get_next_u32()` (id) then `decode_params` — the inverse layout. The id
    /// token is produced via the tokenizer (no direct BigUint dependency).
    fn encode_event_body(contract: &Contract, event_name: &str, params_json: &str) -> SliceData {
        use tvm_abi::token::Tokenizer;
        use tvm_abi::{Param, ParamType};
        let event = contract.event(event_name).unwrap();

        let id_param = Param::new("id", ParamType::Uint(32));
        let id_tokens = Tokenizer::tokenize_all_params(
            std::slice::from_ref(&id_param),
            &serde_json::json!({ "id": event.get_id() }),
        )
        .unwrap();

        let params: serde_json::Value = serde_json::from_str(params_json).unwrap();
        let mut all = id_tokens;
        all.extend(Tokenizer::tokenize_all_params(&event.input_params(), &params).unwrap());

        let builder = TokenValue::pack_values_into_chain(&all, vec![], contract.version()).unwrap();
        SliceData::load_builder(builder).unwrap()
    }

    #[test]
    fn all_expected_events_present_with_distinct_ids() {
        let token = AirContract::TokenContract.load_abi().unwrap();
        let names = [
            "ContractDeployed",
            "TokensPurchased",
            "TokensConsumed",
            "ReservationCancelled",
            "AvailableReduced",
            "FeeBurned",
            "TokensReplenished",
            "ContractDestroyed",
            "ShellWithdrawn",
        ];
        let mut ids = std::collections::HashSet::new();
        for n in names {
            let ev = token
                .event(n)
                .unwrap_or_else(|_| panic!("missing event {n}"));
            assert!(ids.insert(ev.get_id()), "duplicate event id for {n}");
        }

        let sr = AirContract::SuperRoot.load_abi().unwrap();
        assert!(sr.event("RootRegistered").is_ok());
        assert!(sr.event("ManifestRegistered").is_ok());
    }

    #[test]
    fn roundtrip_tokens_purchased() {
        let token = AirContract::TokenContract.load_abi().unwrap();
        let buyer = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let body = encode_event_body(
            &token,
            "TokensPurchased",
            &format!(r#"{{"buyer":"{buyer}","amount":"4875","fee":"125"}}"#),
        );
        let ev = decode_event_body(&token, body).unwrap();
        assert_eq!(
            ev,
            AiRegistryEvent::TokensPurchased {
                buyer: buyer.to_string(),
                amount: 4875,
                fee: 125,
            }
        );
    }

    #[test]
    fn roundtrip_reservation_cancelled() {
        let token = AirContract::TokenContract.load_abi().unwrap();
        let buyer = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let body = encode_event_body(
            &token,
            "ReservationCancelled",
            &format!(r#"{{"buyer":"{buyer}","refundedToBuyer":"2000","carriedSellerOwed":"500"}}"#),
        );
        let ev = decode_event_body(&token, body).unwrap();
        assert_eq!(
            ev,
            AiRegistryEvent::ReservationCancelled {
                buyer: buyer.to_string(),
                refunded: 2000,
                carried_seller_owed: 500,
            }
        );
    }

    #[test]
    fn roundtrip_fee_burned() {
        let token = AirContract::TokenContract.load_abi().unwrap();
        let body = encode_event_body(&token, "FeeBurned", r#"{"amount":"125"}"#);
        assert_eq!(
            decode_event_body(&token, body).unwrap(),
            AiRegistryEvent::FeeBurned { amount: 125 }
        );
    }

    /// Live: fetch a real TokenContract's ext-out (msg_type 2) event messages
    /// from shellnet GraphQL and decode their bodies. Env-gated:
    /// `GOSH_EVENTS_ADDR=<bare-or-0x-token-addr>`.
    #[tokio::test]
    async fn live_decode_real_events() {
        let Ok(addr) = std::env::var("GOSH_EVENTS_ADDR") else {
            return;
        };
        let bare = addr.trim().trim_start_matches("0:");
        let http = reqwest::Client::new();
        let q = serde_json::json!({ "query": format!(
            "{{ blockchain {{ account(account_id:\"{bare}\", dapp_id:\"{bare}\") {{ messages(last:40){{ edges {{ node {{ msg_type body }} }} }} }} }} }}"
        )});
        let resp: serde_json::Value = http
            .post("https://shellnet.ackinacki.org/graphql")
            .json(&q)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = AirContract::TokenContract.load_abi().unwrap();
        let edges = resp
            .pointer("/data/blockchain/account/messages/edges")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut decoded = 0;
        for e in edges {
            if e.pointer("/node/msg_type").and_then(|v| v.as_i64()) == Some(2) {
                if let Some(body) = e.pointer("/node/body").and_then(|v| v.as_str()) {
                    match decode_event_body_b64(&token, body) {
                        Ok(ev) => {
                            eprintln!("decoded ext-out event: {ev:?}");
                            decoded += 1;
                        }
                        Err(err) => eprintln!("body decode skipped: {err}"),
                    }
                }
            }
        }
        eprintln!("decoded {decoded} real ext-out events");
        assert!(
            decoded > 0,
            "expected to decode at least one real ext-out event"
        );
    }

    #[test]
    fn unknown_event_id_errors() {
        let token = AirContract::TokenContract.load_abi().unwrap();
        // A body whose leading u32 is not a known event id.
        use tvm_types::IBitstring;
        let mut b = tvm_types::BuilderData::new();
        b.append_u32(0xdead_beef).unwrap();
        let body = SliceData::load_builder(b).unwrap();
        assert!(decode_event_body(&token, body).is_err());
    }
}
