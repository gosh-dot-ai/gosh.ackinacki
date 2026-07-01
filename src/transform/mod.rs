// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Transform matched blockchain messages into x402-compatible facts
//! for injection into gosh.memory.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::filter::engine::MatchedMessage;
use crate::filter::rules::MsgTypeFilter;

/// Nanotoken (VMSHELL) denomination: 1 EVER = 1_000_000_000 nanotoken.
const NANO: f64 = 1_000_000_000.0;

/// An x402-compatible fact ready for gosh.memory ingestion.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockchainFact {
    pub fact: String,
    pub kind: String,
    pub entities: Vec<String>,
    pub session: i64,
    pub session_date: String,
    pub metadata: Value,
}

/// Convert a matched message into a fact for gosh.memory.
pub fn to_fact(msg: &MatchedMessage, session_num: i64, session_date: &str) -> BlockchainFact {
    let fact_text = build_fact_text(msg);
    let mut entities = Vec::new();
    if let Some(ref src) = msg.src {
        entities.push(src.clone());
    }
    if let Some(ref dst) = msg.dst {
        entities.push(dst.clone());
    }

    let msg_type_str = match msg.msg_type {
        MsgTypeFilter::Internal => "internal",
        MsgTypeFilter::ExtIn => "ext_in",
        MsgTypeFilter::ExtOut => "ext_out",
    };

    let event_type = classify_event_type(msg);

    let metadata = json!({
        "source_id": format!(
            "ackinacki:block:{}:lt:{}",
            msg.block_seq_no, msg.created_lt
        ),
        "semantic_class": classify_message(msg),
        // x402-compatible base fields
        "x402_version": 2,
        "x402_success": true,
        "x402_network": "ackinacki",
        "x402_transaction": format!(
            "block:{}:lt:{}",
            msg.block_seq_no, msg.created_lt
        ),
        "x402_payer": msg.src,
        "x402_payee": msg.dst,
        "x402_amount": msg.value.map(|v| v.to_string()),
        // x402 extensions.ackinacki
        "ackinacki_event_type": event_type,
        "ackinacki_msg_type": msg_type_str,
        "ackinacki_block_seq_no": msg.block_seq_no,
        "ackinacki_thread_id": msg.thread_id,
        "ackinacki_created_at": msg.created_at,
        "ackinacki_method": msg.method_name,
        "ackinacki_bounce": msg.bounce,
    });

    BlockchainFact {
        fact: fact_text,
        kind: "fact".to_string(),
        entities,
        session: session_num,
        session_date: session_date.to_string(),
        metadata,
    }
}

fn build_fact_text(msg: &MatchedMessage) -> String {
    let src = msg.src.as_deref().unwrap_or("external");
    let dst = msg.dst.as_deref().unwrap_or("external");

    match msg.msg_type {
        MsgTypeFilter::Internal => {
            let amount_str = msg
                .value
                .map(|v| format!("{:.2} EVER", v as f64 / NANO))
                .unwrap_or_default();

            match &msg.method_name {
                Some(method) if !amount_str.is_empty() => {
                    format!(
                        "{src} sent {amount_str} to {dst} calling {method}() on Acki Nacki \
                         (block {}, thread {})",
                        msg.block_seq_no, msg.thread_id,
                    )
                }
                Some(method) => {
                    format!(
                        "{src} called {method}() on {dst} on Acki Nacki \
                         (block {}, thread {})",
                        msg.block_seq_no, msg.thread_id,
                    )
                }
                None if !amount_str.is_empty() => {
                    format!(
                        "{src} sent {amount_str} to {dst} on Acki Nacki \
                         (block {}, thread {})",
                        msg.block_seq_no, msg.thread_id,
                    )
                }
                None => {
                    format!(
                        "{src} sent message to {dst} on Acki Nacki \
                         (block {}, thread {})",
                        msg.block_seq_no, msg.thread_id,
                    )
                }
            }
        }
        MsgTypeFilter::ExtIn => match &msg.method_name {
            Some(method) => {
                format!(
                    "External call to {dst} method {method}() on Acki Nacki \
                         (block {}, thread {})",
                    msg.block_seq_no, msg.thread_id,
                )
            }
            None => {
                format!(
                    "External message to {dst} on Acki Nacki \
                         (block {}, thread {})",
                    msg.block_seq_no, msg.thread_id,
                )
            }
        },
        MsgTypeFilter::ExtOut => match &msg.method_name {
            Some(method) => {
                format!(
                    "Event {method}() emitted by {src} on Acki Nacki \
                         (block {}, thread {})",
                    msg.block_seq_no, msg.thread_id,
                )
            }
            None => {
                format!(
                    "Event emitted by {src} on Acki Nacki \
                         (block {}, thread {})",
                    msg.block_seq_no, msg.thread_id,
                )
            }
        },
    }
}

/// Classify message semantically for the metadata field.
fn classify_message(msg: &MatchedMessage) -> &'static str {
    match &msg.method_name {
        Some(m) if m.contains("transfer") || m.contains("send") => "payment_settlement",
        Some(m) if m.contains("deploy") || m.contains("constructor") => "contract_deployment",
        Some(m) if m.contains("confirm") => "multisig_confirmation",
        Some(m) if m.contains("submit") => "multisig_submission",
        Some(m) if m.contains("Config") || m.contains("mintshell") => "dapp_config",
        _ if msg.msg_type == MsgTypeFilter::ExtOut => "contract_event",
        _ if msg.value.unwrap_or(0) > 0 => "value_transfer",
        _ => "message",
    }
}

/// x402 extensions.ackinacki.event_type — structured event classification.
///
/// Types:
///   payment  — token transfer (sendTransaction, transfer, sendTokens)
///   deploy   — contract deployment (constructor with StateInit)
///   call     — method invocation (submitTransaction, any function call)
///   confirm  — multisig confirmation (confirmTransaction)
///   event    — contract-emitted event (ext_out messages)
///   dapp_config — DApp ID operations (deployNewConfigCustom, fund, setNewConfig)
///   message  — unclassified internal/external message
fn classify_event_type(msg: &MatchedMessage) -> &'static str {
    // ext_out = contract event, always
    if msg.msg_type == MsgTypeFilter::ExtOut {
        return "event";
    }

    match &msg.method_name {
        // DApp config: DApp ID lifecycle (must be before deploy — deployNewConfigCustom)
        Some(m)
            if m.contains("Config")
                || m.contains("mintshell")
                || m == "setNewConfig"
                || m == "deployNewConfigCustom" =>
        {
            "dapp_config"
        }
        // Payment: explicit token sends
        Some(m)
            if m.contains("transfer")
                || m == "sendTransaction"
                || m == "sendTokens"
                || m == "sendTokensDirect" =>
        {
            "payment"
        }
        // Deploy: constructor or explicit deploy methods
        Some(m) if m == "constructor" || m.contains("deploy") || m.contains("Deploy") => "deploy",
        // Confirm: multisig confirmation
        Some(m) if m.contains("confirm") || m.contains("Confirm") => "confirm",
        // Submit / any other named call
        Some(_) => "call",
        // No method decoded
        None if msg.msg_type == MsgTypeFilter::ExtIn => "call",
        None if msg.value.unwrap_or(0) > 0 => "payment",
        None => "message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(
        msg_type: MsgTypeFilter,
        src: Option<&str>,
        dst: Option<&str>,
        value: Option<u128>,
        method_name: Option<&str>,
    ) -> MatchedMessage {
        MatchedMessage {
            src: src.map(String::from),
            dst: dst.map(String::from),
            msg_type,
            value,
            method_name: method_name.map(String::from),
            body: None,
            created_at: 1000,
            created_lt: 2000,
            bounce: false,
            block_seq_no: 42,
            thread_id: "ff".to_string(),
        }
    }

    #[test]
    fn to_fact_internal_with_value_and_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:aaa"),
            Some("0:bbb"),
            Some(1_500_000_000), // 1.5 EVER
            Some("transfer"),
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert!(fact.fact.contains("0:aaa"));
        assert!(fact.fact.contains("0:bbb"));
        assert!(fact.fact.contains("1.50 EVER"));
        assert!(fact.fact.contains("transfer()"));
        assert!(fact.fact.contains("block 42"));
        assert_eq!(fact.kind, "fact");
        assert_eq!(fact.session, 1);
        assert_eq!(fact.session_date, "2026-03-30");
    }

    #[test]
    fn to_fact_internal_with_value_no_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:aaa"),
            Some("0:bbb"),
            Some(2_000_000_000),
            None,
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert!(fact.fact.contains("sent 2.00 EVER"));
        assert!(!fact.fact.contains("calling"));
    }

    #[test]
    fn to_fact_internal_no_value_with_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:aaa"),
            Some("0:bbb"),
            None,
            Some("deploy"),
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        // When value is None, amount_str is empty, so it should use the "Some(method)" branch
        assert!(fact.fact.contains("called deploy()"));
        assert!(!fact.fact.contains("EVER"));
    }

    #[test]
    fn to_fact_internal_zero_value_no_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:aaa"),
            Some("0:bbb"),
            Some(0),
            None,
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        // 0 value formats as "0.00 EVER" which is non-empty
        assert!(fact.fact.contains("sent 0.00 EVER"));
    }

    #[test]
    fn to_fact_ext_in_with_method() {
        let msg = make_msg(
            MsgTypeFilter::ExtIn,
            None,
            Some("0:bbb"),
            None,
            Some("submitTransaction"),
        );
        let fact = to_fact(&msg, 2, "2026-03-30");
        assert!(fact.fact.contains("External call"));
        assert!(fact.fact.contains("0:bbb"));
        assert!(fact.fact.contains("submitTransaction()"));
    }

    #[test]
    fn to_fact_ext_in_no_method() {
        let msg = make_msg(MsgTypeFilter::ExtIn, None, Some("0:bbb"), None, None);
        let fact = to_fact(&msg, 2, "2026-03-30");
        assert!(fact.fact.contains("External message to 0:bbb"));
    }

    #[test]
    fn to_fact_ext_out_with_method() {
        let msg = make_msg(
            MsgTypeFilter::ExtOut,
            Some("0:aaa"),
            None,
            None,
            Some("TransferAccepted"),
        );
        let fact = to_fact(&msg, 3, "2026-03-30");
        assert!(fact.fact.contains("Event TransferAccepted()"));
        assert!(fact.fact.contains("emitted by 0:aaa"));
    }

    #[test]
    fn to_fact_ext_out_no_method() {
        let msg = make_msg(MsgTypeFilter::ExtOut, Some("0:aaa"), None, None, None);
        let fact = to_fact(&msg, 3, "2026-03-30");
        assert!(fact.fact.contains("Event emitted by 0:aaa"));
    }

    #[test]
    fn to_fact_ext_out_no_src() {
        let msg = make_msg(MsgTypeFilter::ExtOut, None, None, None, None);
        let fact = to_fact(&msg, 3, "2026-03-30");
        // src is None -> "external"
        assert!(fact.fact.contains("emitted by external"));
    }

    #[test]
    fn classify_transfer() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, None, Some("transfer"));
        assert_eq!(classify_message(&msg), "payment_settlement");
    }

    #[test]
    fn classify_send() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("sendTransaction"),
        );
        assert_eq!(classify_message(&msg), "payment_settlement");
    }

    #[test]
    fn classify_deploy() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("deployContract"),
        );
        assert_eq!(classify_message(&msg), "contract_deployment");
    }

    #[test]
    fn classify_confirm() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("confirmTransaction"),
        );
        assert_eq!(classify_message(&msg), "multisig_confirmation");
    }

    #[test]
    fn classify_submit() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("submitTransaction"),
        );
        assert_eq!(classify_message(&msg), "multisig_submission");
    }

    #[test]
    fn classify_ext_out_event() {
        let msg = make_msg(MsgTypeFilter::ExtOut, None, None, None, None);
        assert_eq!(classify_message(&msg), "contract_event");
    }

    #[test]
    fn classify_value_transfer() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            Some(1_000_000_000),
            None,
        );
        assert_eq!(classify_message(&msg), "value_transfer");
    }

    #[test]
    fn classify_generic_message() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, Some(0), None);
        assert_eq!(classify_message(&msg), "message");
    }

    #[test]
    fn classify_generic_no_value() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, None, None);
        assert_eq!(classify_message(&msg), "message");
    }

    #[test]
    fn metadata_has_x402_fields() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:src"),
            Some("0:dst"),
            Some(100),
            Some("transfer"),
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        let meta = &fact.metadata;
        // x402 base
        assert_eq!(meta["x402_version"], 2);
        assert_eq!(meta["x402_success"], true);
        assert_eq!(meta["x402_network"], "ackinacki");
        assert!(meta.get("x402_transaction").is_some());
        assert!(meta.get("x402_payer").is_some());
        assert!(meta.get("x402_payee").is_some());
        assert!(meta.get("x402_amount").is_some());
        // extensions.ackinacki
        assert!(meta.get("ackinacki_event_type").is_some());
        assert!(meta.get("ackinacki_msg_type").is_some());
        assert!(meta.get("ackinacki_block_seq_no").is_some());
        assert!(meta.get("ackinacki_thread_id").is_some());
        assert!(meta.get("ackinacki_created_at").is_some());
        assert!(meta.get("ackinacki_method").is_some());
        assert!(meta.get("ackinacki_bounce").is_some());
        assert!(meta.get("source_id").is_some());
        assert!(meta.get("semantic_class").is_some());
    }

    #[test]
    fn entities_contains_src_and_dst() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:src_addr"),
            Some("0:dst_addr"),
            Some(100),
            None,
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert!(fact.entities.contains(&"0:src_addr".to_string()));
        assert!(fact.entities.contains(&"0:dst_addr".to_string()));
        assert_eq!(fact.entities.len(), 2);
    }

    #[test]
    fn entities_only_src_when_no_dst() {
        let msg = make_msg(MsgTypeFilter::ExtOut, Some("0:src_addr"), None, None, None);
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert_eq!(fact.entities, vec!["0:src_addr".to_string()]);
    }

    #[test]
    fn entities_only_dst_when_no_src() {
        let msg = make_msg(MsgTypeFilter::ExtIn, None, Some("0:dst_addr"), None, None);
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert_eq!(fact.entities, vec!["0:dst_addr".to_string()]);
    }

    #[test]
    fn entities_empty_when_no_addrs() {
        let msg = make_msg(MsgTypeFilter::ExtOut, None, None, None, None);
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert!(fact.entities.is_empty());
    }

    #[test]
    fn source_id_format() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:a"),
            Some("0:b"),
            Some(0),
            None,
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        assert_eq!(fact.metadata["source_id"], "ackinacki:block:42:lt:2000");
    }

    // --- classify_event_type tests ---

    #[test]
    fn event_type_payment_transfer() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, None, Some("transfer"));
        assert_eq!(classify_event_type(&msg), "payment");
    }

    #[test]
    fn event_type_payment_send_transaction() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("sendTransaction"),
        );
        assert_eq!(classify_event_type(&msg), "payment");
    }

    #[test]
    fn event_type_payment_send_tokens() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("sendTokens"),
        );
        assert_eq!(classify_event_type(&msg), "payment");
    }

    #[test]
    fn event_type_payment_value_no_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            Some(1_000_000_000),
            None,
        );
        assert_eq!(classify_event_type(&msg), "payment");
    }

    #[test]
    fn event_type_deploy_constructor() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("constructor"),
        );
        assert_eq!(classify_event_type(&msg), "deploy");
    }

    #[test]
    fn event_type_deploy_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("deployContract"),
        );
        assert_eq!(classify_event_type(&msg), "deploy");
    }

    #[test]
    fn event_type_confirm() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("confirmTransaction"),
        );
        assert_eq!(classify_event_type(&msg), "confirm");
    }

    #[test]
    fn event_type_event_ext_out() {
        let msg = make_msg(MsgTypeFilter::ExtOut, None, None, None, None);
        assert_eq!(classify_event_type(&msg), "event");
    }

    #[test]
    fn event_type_event_ext_out_with_method() {
        let msg = make_msg(
            MsgTypeFilter::ExtOut,
            None,
            None,
            None,
            Some("TransferAccepted"),
        );
        assert_eq!(classify_event_type(&msg), "event");
    }

    #[test]
    fn event_type_dapp_config() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("deployNewConfigCustom"),
        );
        assert_eq!(classify_event_type(&msg), "dapp_config");
    }

    #[test]
    fn event_type_dapp_set_config() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("setNewConfig"),
        );
        assert_eq!(classify_event_type(&msg), "dapp_config");
    }

    #[test]
    fn event_type_call_submit() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("submitTransaction"),
        );
        assert_eq!(classify_event_type(&msg), "call");
    }

    #[test]
    fn event_type_call_unknown_method() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            None,
            None,
            None,
            Some("customMethod"),
        );
        assert_eq!(classify_event_type(&msg), "call");
    }

    #[test]
    fn event_type_call_ext_in_no_method() {
        let msg = make_msg(MsgTypeFilter::ExtIn, None, None, None, None);
        assert_eq!(classify_event_type(&msg), "call");
    }

    #[test]
    fn event_type_message_no_value_no_method() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, Some(0), None);
        assert_eq!(classify_event_type(&msg), "message");
    }

    #[test]
    fn event_type_message_none_value_no_method() {
        let msg = make_msg(MsgTypeFilter::Internal, None, None, None, None);
        assert_eq!(classify_event_type(&msg), "message");
    }

    #[test]
    fn event_type_in_metadata() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:a"),
            Some("0:b"),
            None,
            Some("transfer"),
        );
        let fact = to_fact(&msg, 1, "2026-04-05");
        assert_eq!(fact.metadata["ackinacki_event_type"], "payment");
    }

    #[test]
    fn blockchain_fact_serde_roundtrip() {
        let msg = make_msg(
            MsgTypeFilter::Internal,
            Some("0:a"),
            Some("0:b"),
            Some(1_000_000_000),
            Some("transfer"),
        );
        let fact = to_fact(&msg, 1, "2026-03-30");
        let json = serde_json::to_string(&fact).unwrap();
        let restored: BlockchainFact = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.fact, fact.fact);
        assert_eq!(restored.kind, "fact");
        assert_eq!(restored.session, 1);
    }
}
