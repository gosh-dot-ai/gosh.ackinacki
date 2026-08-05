// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Filter engine: iterates messages in a decoded block, applies rules,
//! yields matched messages for transformation.

use std::collections::HashMap;

use anyhow::Result;
use tvm_types::SliceData;

// Block-stream decoding (feature-gated): node + the block-iteration tvm_block API.
#[cfg(feature = "block-stream")]
use crate::decoder::block::DecodedBlock;
#[cfg(feature = "block-stream")]
use crate::filter::rules::{FilterConfig, MsgTypeFilter};
#[cfg(feature = "block-stream")]
use node::bls::envelope::BLSSignedEnvelope;
#[cfg(feature = "block-stream")]
use tvm_block::{CommonMsgInfo, Deserializable, HashmapAugType, Message, MsgAddressInt};
#[cfg(feature = "block-stream")]
use tvm_types::HashmapType;

/// A message that passed the filter.
#[cfg(feature = "block-stream")]
pub struct MatchedMessage {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub msg_type: MsgTypeFilter,
    pub value: Option<u128>,
    pub method_name: Option<String>,
    pub body: Option<SliceData>,
    pub created_at: u32,
    pub created_lt: u64,
    pub bounce: bool,
    pub block_seq_no: u32,
    pub thread_id: String,
}

/// ABI registry: maps contract addresses to loaded ABI JSON, plus **global**
/// ABIs matched by contract *type* when the address is unknown ahead of time
/// (e.g. per-model inference order books, per-trader PrivateNotes).
/// Used for decoding message bodies.
pub struct AbiRegistry {
    abis: HashMap<String, tvm_abi::Contract>,
    global: Vec<tvm_abi::Contract>,
}

impl AbiRegistry {
    pub fn new() -> Self {
        Self {
            abis: HashMap::new(),
            global: Vec::new(),
        }
    }

    /// A registry preloaded with the inference-market contract family
    /// (`InferenceOrderBook`, `PrivateNote`, `RootPN`) as **global** ABIs, so
    /// market events decode from ANY order book / note without knowing their
    /// addresses upfront. Pair with [`crate::filter::rules::FilterRule::inference_market_events`].
    pub fn with_inference_market() -> Result<Self> {
        let mut reg = Self::new();
        reg.register_global(crate::inference::abi::INFERENCE_ORDER_BOOK_ABI_JSON)?;
        reg.register_global(crate::inference::abi::PRIVATE_NOTE_ABI_JSON)?;
        reg.register_global(crate::inference::abi::ROOT_PN_ABI_JSON)?;
        Ok(reg)
    }

    pub fn register(&mut self, address: &str, abi_json: &str) -> Result<()> {
        let contract = tvm_abi::Contract::load(abi_json.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to load ABI for {address}: {e}"))?;
        self.abis.insert(address.to_string(), contract);
        Ok(())
    }

    /// Register an ABI tried for **every** message whose address has no
    /// per-address entry. Method/event ids are signature-derived, so decoding
    /// against a foreign global ABI simply misses; order globals from most to
    /// least specific.
    pub fn register_global(&mut self, abi_json: &str) -> Result<()> {
        let contract = tvm_abi::Contract::load(abi_json.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to load global ABI: {e}"))?;
        self.global.push(contract);
        Ok(())
    }

    /// Try to decode a method name from the message body: the address-bound
    /// ABI first, then the global ABIs in registration order.
    /// Checks function input IDs, event IDs, and function output IDs.
    pub fn decode_method(&self, address: &str, body: &SliceData) -> Option<String> {
        let mut body_clone = body.clone();
        let func_id = body_clone.get_next_u32().ok()?;
        if let Some(contract) = self.abis.get(address) {
            if let Some(name) = Self::method_by_id(contract, func_id) {
                return Some(name);
            }
        }
        self.global
            .iter()
            .find_map(|c| Self::method_by_id(c, func_id))
    }

    fn method_by_id(contract: &tvm_abi::Contract, func_id: u32) -> Option<String> {
        // Check event IDs first (relevant for ext_out messages)
        for event in contract.events().values() {
            if event.get_function_id() == func_id {
                return Some(event.name.clone());
            }
        }
        for func in contract.functions().values() {
            if func.get_input_id() == func_id {
                return Some(func.name.clone());
            }
            if func.get_output_id() == func_id {
                return Some(func.name.clone());
            }
        }
        None
    }
}

impl Default for AbiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "block-stream")]
fn format_address(addr: &MsgAddressInt) -> String {
    match addr {
        MsgAddressInt::AddrStd(std) => {
            format!(
                "{}:{}",
                std.workchain_id,
                hex::encode(std.address.get_bytestring(0))
            )
        }
        MsgAddressInt::AddrVar(var) => {
            format!(
                "{}:{}",
                var.workchain_id,
                hex::encode(var.address.get_bytestring(0))
            )
        }
    }
}

/// Try to extract MsgAddressInt from MsgAddressIntOrNone.
#[cfg(feature = "block-stream")]
fn address_from_int_or_none(addr: &tvm_block::MsgAddressIntOrNone) -> Option<MsgAddressInt> {
    match addr {
        tvm_block::MsgAddressIntOrNone::Some(a) => Some(a.clone()),
        tvm_block::MsgAddressIntOrNone::None => None,
    }
}

/// Process a decoded block: iterate all messages, apply filter, return matches.
#[cfg(feature = "block-stream")]
pub fn process_block(
    block: &DecodedBlock,
    config: &FilterConfig,
    abi_registry: &AbiRegistry,
) -> Vec<MatchedMessage> {
    let mut matched = Vec::new();

    let acki_block = block.envelope.data();
    let tvm_block = acki_block.tvm_block();

    let block_info = match tvm_block.read_info() {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("failed to read block info: {e}");
            return matched;
        }
    };
    let block_seq_no = block_info.seq_no();

    let extra = match tvm_block.read_extra() {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("failed to read block extra: {e}");
            return matched;
        }
    };

    let thread_id = format!("{:x}", acki_block.common_section().thread_id());

    let account_blocks = match extra.read_account_blocks() {
        Ok(ab) => ab,
        Err(e) => {
            tracing::error!("failed to read account blocks: {e}");
            return matched;
        }
    };

    let _ = account_blocks.iterate_objects(|account_block| {
        let _ = account_block.transactions().iterate_slices(|_, tx_slice| {
            let cell = match tx_slice.reference(0) {
                Ok(c) => c,
                Err(_) => return Ok(true),
            };
            let tx = match tvm_block::Transaction::construct_from(&mut SliceData::load_cell(cell)?)
            {
                Ok(t) => t,
                Err(_) => return Ok(true),
            };

            // Process in_msg
            if let Some(in_msg_cell) = tx.in_msg_cell() {
                if let Ok(msg) = Message::construct_from(&mut SliceData::load_cell(in_msg_cell)?) {
                    if let Some(m) =
                        try_match_message(&msg, config, abi_registry, block_seq_no, &thread_id)
                    {
                        matched.push(m);
                    }
                }
            }

            // Process out_msgs
            let _ = tx.out_msgs.iterate_slices(|out_slice| {
                if let Ok(cell) = out_slice.reference(0) {
                    if let Ok(msg) = Message::construct_from(&mut SliceData::load_cell(cell)?) {
                        if let Some(m) =
                            try_match_message(&msg, config, abi_registry, block_seq_no, &thread_id)
                        {
                            matched.push(m);
                        }
                    }
                }
                Ok(true)
            });

            Ok(true)
        });
        Ok(true)
    });

    matched
}

#[cfg(feature = "block-stream")]
fn try_match_message(
    msg: &Message,
    config: &FilterConfig,
    abi_registry: &AbiRegistry,
    block_seq_no: u32,
    thread_id: &str,
) -> Option<MatchedMessage> {
    let (msg_type, src, dst, value, created_at, created_lt, bounce) = match msg.header() {
        CommonMsgInfo::IntMsgInfo(h) => {
            let src = address_from_int_or_none(&h.src).map(|a| format_address(&a));
            let dst = format_address(&h.dst);
            let value = h.value.grams.as_u128();
            (
                MsgTypeFilter::Internal,
                src,
                Some(dst),
                Some(value),
                h.created_at.as_u32(),
                h.created_lt,
                h.bounce,
            )
        }
        CommonMsgInfo::ExtInMsgInfo(h) => {
            let dst = format_address(&h.dst);
            (MsgTypeFilter::ExtIn, None, Some(dst), None, 0, 0, false)
        }
        CommonMsgInfo::ExtOutMsgInfo(h) => {
            let src = address_from_int_or_none(&h.src).map(|a| format_address(&a));
            (
                MsgTypeFilter::ExtOut,
                src,
                None,
                None,
                h.created_at.as_u32(),
                h.created_lt,
                false,
            )
        }
    };

    // Try ABI decode for method name
    let body = msg.body();
    let method_name = body.as_ref().and_then(|b| {
        let addr: &str = dst.as_deref().or(src.as_deref())?;
        abi_registry.decode_method(addr, b)
    });

    // Apply filter
    if !config.matches(
        src.as_deref(),
        dst.as_deref(),
        &msg_type,
        method_name.as_deref(),
    ) {
        return None;
    }

    Some(MatchedMessage {
        src,
        dst,
        msg_type,
        value,
        method_name,
        body: body.clone(),
        created_at,
        created_lt,
        bounce,
        block_seq_no,
        thread_id: thread_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "block-stream")]
    use tvm_block::{MsgAddrStd, MsgAddressInt, MsgAddressIntOrNone};
    #[cfg(feature = "block-stream")]
    use tvm_types::AccountId;

    // Minimal ABI JSON with one function for testing ABI registry.
    const TEST_ABI_JSON: &str = r#"{
        "ABI version": 2,
        "version": "2.4",
        "header": ["pubkey", "time", "expire"],
        "functions": [
            {
                "name": "confirmTransaction",
                "inputs": [{"name":"transactionId","type":"uint64"}],
                "outputs": []
            },
            {
                "name": "sendTransaction",
                "inputs": [
                    {"name":"dest","type":"address"},
                    {"name":"value","type":"uint128"},
                    {"name":"cc","type":"map(uint32,varuint32)"},
                    {"name":"bounce","type":"bool"},
                    {"name":"flags","type":"uint8"},
                    {"name":"payload","type":"cell"}
                ],
                "outputs": [{"name":"value0","type":"address"}]
            }
        ],
        "events": [],
        "fields": []
    }"#;

    #[cfg(feature = "block-stream")]
    fn make_addr_std(wc: i8, bytes: &[u8; 32]) -> MsgAddressInt {
        MsgAddressInt::AddrStd(MsgAddrStd::with_address(
            None,
            wc,
            AccountId::from_raw(bytes.to_vec(), 256),
        ))
    }

    #[test]
    fn abi_registry_new_is_empty() {
        let reg = AbiRegistry::new();
        assert!(reg.abis.is_empty());
    }

    #[test]
    fn abi_registry_default_is_empty() {
        let reg = AbiRegistry::default();
        assert!(reg.abis.is_empty());
    }

    #[test]
    fn abi_registry_register_valid_abi() {
        let mut reg = AbiRegistry::new();
        let result = reg.register("0:abc", TEST_ABI_JSON);
        assert!(result.is_ok());
        assert!(reg.abis.contains_key("0:abc"));
    }

    #[test]
    fn abi_registry_register_invalid_abi() {
        let mut reg = AbiRegistry::new();
        let result = reg.register("0:abc", "not valid json");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("failed to load ABI"));
    }

    #[test]
    fn abi_registry_register_empty_json_object() {
        let mut reg = AbiRegistry::new();
        let result = reg.register("0:abc", "{}");
        // Empty JSON object is not a valid ABI
        assert!(result.is_err());
    }

    #[test]
    fn abi_registry_decode_method_unknown_address() {
        let reg = AbiRegistry::new();
        let body = SliceData::new(vec![0x00, 0x00, 0x00, 0x01, 0x80]);
        assert!(reg.decode_method("0:unknown", &body).is_none());
    }

    #[test]
    fn abi_registry_decode_method_unknown_func_id() {
        let mut reg = AbiRegistry::new();
        reg.register("0:abc", TEST_ABI_JSON).unwrap();
        // Use a func_id that doesn't match any function
        let body = SliceData::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0x80]);
        assert!(reg.decode_method("0:abc", &body).is_none());
    }

    #[test]
    fn abi_registry_decode_method_empty_body() {
        let mut reg = AbiRegistry::new();
        reg.register("0:abc", TEST_ABI_JSON).unwrap();
        // Body too short for a u32 func_id
        let body = SliceData::new(vec![0x80]);
        assert!(reg.decode_method("0:abc", &body).is_none());
    }

    #[cfg(feature = "block-stream")]
    #[test]
    fn format_address_addr_std() {
        let bytes = [0xab; 32];
        let addr = make_addr_std(0, &bytes);
        let formatted = format_address(&addr);
        assert_eq!(formatted, format!("0:{}", hex::encode(bytes)));
    }

    #[cfg(feature = "block-stream")]
    #[test]
    fn format_address_addr_std_negative_workchain() {
        let bytes = [0x01; 32];
        let addr = make_addr_std(-1, &bytes);
        let formatted = format_address(&addr);
        assert_eq!(formatted, format!("-1:{}", hex::encode(bytes)));
    }

    #[cfg(feature = "block-stream")]
    #[test]
    fn format_address_addr_std_zero_bytes() {
        let bytes = [0x00; 32];
        let addr = make_addr_std(0, &bytes);
        let formatted = format_address(&addr);
        assert_eq!(formatted, format!("0:{}", hex::encode(bytes)));
    }

    #[cfg(feature = "block-stream")]
    #[test]
    fn address_from_int_or_none_some() {
        let bytes = [0xab; 32];
        let addr = make_addr_std(0, &bytes);
        let wrapped = MsgAddressIntOrNone::Some(addr.clone());
        let result = address_from_int_or_none(&wrapped);
        assert!(result.is_some());
    }

    #[cfg(feature = "block-stream")]
    #[test]
    fn address_from_int_or_none_none() {
        let wrapped = MsgAddressIntOrNone::None;
        let result = address_from_int_or_none(&wrapped);
        assert!(result.is_none());
    }

    #[test]
    fn abi_registry_register_overwrite() {
        let mut reg = AbiRegistry::new();
        reg.register("0:abc", TEST_ABI_JSON).unwrap();
        assert_eq!(reg.abis.len(), 1);
        // Register again with same address overwrites
        reg.register("0:abc", TEST_ABI_JSON).unwrap();
        assert_eq!(reg.abis.len(), 1);
    }

    #[test]
    fn abi_registry_register_multiple_addresses() {
        let mut reg = AbiRegistry::new();
        reg.register("0:aaa", TEST_ABI_JSON).unwrap();
        reg.register("0:bbb", TEST_ABI_JSON).unwrap();
        assert_eq!(reg.abis.len(), 2);
        assert!(reg.abis.contains_key("0:aaa"));
        assert!(reg.abis.contains_key("0:bbb"));
    }

    /// Build a message body whose leading u32 is `id` (what decode_method reads).
    fn body_with_id(id: u32) -> SliceData {
        SliceData::new([id.to_be_bytes().to_vec(), vec![0x80]].concat())
    }

    #[test]
    fn global_abi_decodes_events_from_unknown_addresses() {
        // Order books / notes are deployed dynamically — their addresses are
        // unknown upfront. The inference-market registry must decode their
        // events via the GLOBAL ABIs for ANY address.
        let reg = AbiRegistry::with_inference_market().unwrap();
        let ob = crate::inference::abi::order_book_abi().unwrap();
        for name in ["InferenceFilled", "InferenceOrderPlaced"] {
            let ev = ob.events().values().find(|e| e.name == name).unwrap();
            let body = body_with_id(ev.get_function_id());
            assert_eq!(
                reg.decode_method("0:some-never-registered-book", &body)
                    .as_deref(),
                Some(name)
            );
        }
        // A note-side event decodes too (PrivateNote ABI is global as well).
        let note = crate::inference::abi::note_abi().unwrap();
        let ev = note
            .events()
            .values()
            .find(|e| e.name == "InferenceFilledConfirmed")
            .unwrap();
        assert_eq!(
            reg.decode_method("0:any-note", &body_with_id(ev.get_function_id()))
                .as_deref(),
            Some("InferenceFilledConfirmed")
        );
    }

    #[test]
    fn per_address_abi_takes_precedence_over_global() {
        let mut reg = AbiRegistry::with_inference_market().unwrap();
        reg.register("0:pinned", TEST_ABI_JSON).unwrap();
        // The pinned ABI still decodes its own methods…
        let pinned = tvm_abi::Contract::load(TEST_ABI_JSON.as_bytes()).unwrap();
        let f = pinned.function("confirmTransaction").unwrap();
        let body = body_with_id(f.get_input_id());
        assert_eq!(
            reg.decode_method("0:pinned", &body).as_deref(),
            Some("confirmTransaction")
        );
        // …and a global-only id still resolves on that address (fallback).
        let ob = crate::inference::abi::order_book_abi().unwrap();
        let ev = ob
            .events()
            .values()
            .find(|e| e.name == "InferenceExecuted")
            .unwrap();
        assert_eq!(
            reg.decode_method("0:pinned", &body_with_id(ev.get_function_id()))
                .as_deref(),
            Some("InferenceExecuted")
        );
    }
}
