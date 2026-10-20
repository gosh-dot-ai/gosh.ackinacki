// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Transaction operations: submitTransaction + confirmTransaction.

use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;
use tvm_abi::token::Tokenizer;
use tvm_block::{
    ExternalInboundMessageHeader, Message, MsgAddressExt, MsgAddressInt, Serializable,
};
use tvm_types::{ed25519_create_private_key, write_boc, SliceData};

use super::contracts::MULTISIG_ABI;

/// Encode a submitTransaction external message.
pub fn encode_submit_transaction(
    wallet_address: &MsgAddressInt,
    dest: &str,
    value: u128,
    bounce: bool,
    signer_secret: &str,
) -> Result<String> {
    let params = serde_json::json!({
        "dest": dest,
        "value": value.to_string(),
        "cc": {},
        "bounce": bounce,
        "flag": 1,
        "payload": "",
    });
    encode_call(wallet_address, "submitTransaction", &params, signer_secret)
}

/// Encode a confirmTransaction external message.
pub fn encode_confirm_transaction(
    wallet_address: &MsgAddressInt,
    transaction_id: u64,
    signer_secret: &str,
) -> Result<String> {
    let params = serde_json::json!({
        "transactionId": transaction_id.to_string(),
    });
    encode_call(wallet_address, "confirmTransaction", &params, signer_secret)
}

/// Encode a sendTransaction external message (single-custodian fast path).
pub fn encode_send_transaction(
    wallet_address: &MsgAddressInt,
    dest: &str,
    value: u128,
    bounce: bool,
    signer_secret: &str,
) -> Result<String> {
    let params = serde_json::json!({
        "dest": dest,
        "value": value.to_string(),
        "cc": {},
        "bounce": bounce,
        "flags": 1,
        "payload": "",
    });
    encode_call(wallet_address, "sendTransaction", &params, signer_secret)
}

/// Encode a `submitTransaction` external message threading `cc` (extra
/// currencies, e.g. `{2: shellAmount}` for SHELL) + `flag` + a `payload` cell
/// (the ABI-encoded internal body of the forwarded call, `""` for a plain
/// transfer). Whether the call executes immediately (1-sig wallet) or queues
/// (needs `confirmTransaction`) is decided on-chain by the wallet's
/// `reqConfirms`, not here (§6).
#[allow(clippy::too_many_arguments)]
pub fn encode_submit_transaction_full(
    wallet_address: &MsgAddressInt,
    dest: &str,
    value: u128,
    cc: &std::collections::BTreeMap<u32, u128>,
    bounce: bool,
    flag: u8,
    payload_boc_b64: &str,
    signer_secret: &str,
) -> Result<String> {
    let cc_json: serde_json::Map<String, serde_json::Value> = cc
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
        .collect();
    let params = serde_json::json!({
        "dest": dest,
        "value": value.to_string(),
        "cc": serde_json::Value::Object(cc_json),
        "bounce": bounce,
        "flag": flag,
        "payload": payload_boc_b64,
    });
    encode_call(wallet_address, "submitTransaction", &params, signer_secret)
}

/// Encode an external call to any contract with a given ABI.
/// Used for SwarmRoot.deployWallet and other non-multisig calls.
pub fn encode_external_call(
    addr_str: &str,
    abi: &tvm_abi::Contract,
    function_name: &str,
    params: &serde_json::Value,
    signer_secret: &str,
) -> Result<String> {
    let parts: Vec<&str> = addr_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        bail!("invalid address format");
    }
    let wc: i8 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("bad workchain"))?;
    let addr_bytes = hex::decode(parts[1])?;
    // `AccountId::from_raw(data, 256)` panics on `data.len() != 32`, so guard
    // here. Callers may pass malformed addresses (mistyped hex) and we must
    // surface that as a Result error rather than a process abort.
    if addr_bytes.len() != 32 {
        bail!(
            "address account-id must be exactly 32 bytes (got {})",
            addr_bytes.len()
        );
    }
    let address =
        MsgAddressInt::with_standart(None, wc, tvm_types::AccountId::from_raw(addr_bytes, 256))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    encode_call_with_abi(&address, abi, function_name, params, signer_secret)
}

fn encode_call_with_abi(
    address: &MsgAddressInt,
    abi: &tvm_abi::Contract,
    function_name: &str,
    params: &serde_json::Value,
    signer_secret: &str,
) -> Result<String> {
    let signer_bytes = hex::decode(signer_secret)?;
    if signer_bytes.len() != 32 {
        bail!("signer secret must be 32 bytes");
    }
    let signer_key = SigningKey::from_bytes(
        &signer_bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad key"))?,
    );

    let function = abi
        .function(function_name)
        .map_err(|e| anyhow::anyhow!("function {function_name} not found: {e}"))?;

    let header = super::build_header(&signer_key);
    let header_tokens = Tokenizer::tokenize_optional_params(function.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("header tokenize: {e}"))?;
    let input_tokens = Tokenizer::tokenize_all_params(function.input_params(), params)
        .map_err(|e| anyhow::anyhow!("input tokenize: {e}"))?;

    let sign_key =
        ed25519_create_private_key(&signer_bytes).map_err(|e| anyhow::anyhow!("privkey: {e}"))?;

    let body_builder = function
        .encode_input(
            &header_tokens,
            &input_tokens,
            false,
            Some(&sign_key),
            Some(address.clone()),
        )
        .map_err(|e| anyhow::anyhow!("encode_input: {e}"))?;

    let body =
        SliceData::load_builder(body_builder).map_err(|e| anyhow::anyhow!("load body: {e}"))?;

    let mut msg = Message::with_ext_in_header(ExternalInboundMessageHeader {
        src: MsgAddressExt::default(),
        dst: address.clone(),
        import_fee: Default::default(),
    });
    msg.set_body(body);

    let msg_cell = msg
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize msg: {e}"))?;
    let boc = write_boc(&msg_cell).map_err(|e| anyhow::anyhow!("write BOC: {e}"))?;
    Ok(super::base64_encode(&boc))
}

fn encode_call(
    address: &MsgAddressInt,
    function_name: &str,
    params: &serde_json::Value,
    signer_secret: &str,
) -> Result<String> {
    let signer_bytes = hex::decode(signer_secret)?;
    if signer_bytes.len() != 32 {
        bail!("signer secret must be 32 bytes");
    }
    let signer_key = SigningKey::from_bytes(
        &signer_bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad key"))?,
    );

    let abi = &*MULTISIG_ABI;
    let function = abi
        .function(function_name)
        .map_err(|e| anyhow::anyhow!("function {function_name} not found: {e}"))?;

    let header = super::build_header(&signer_key);
    let header_tokens = Tokenizer::tokenize_optional_params(function.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("header tokenize: {e}"))?;
    let input_tokens = Tokenizer::tokenize_all_params(function.input_params(), params)
        .map_err(|e| anyhow::anyhow!("input tokenize: {e}"))?;

    let sign_key =
        ed25519_create_private_key(&signer_bytes).map_err(|e| anyhow::anyhow!("privkey: {e}"))?;

    let body_builder = function
        .encode_input(
            &header_tokens,
            &input_tokens,
            false,
            Some(&sign_key),
            Some(address.clone()),
        )
        .map_err(|e| anyhow::anyhow!("encode_input: {e}"))?;

    let body =
        SliceData::load_builder(body_builder).map_err(|e| anyhow::anyhow!("load body: {e}"))?;

    let mut msg = Message::with_ext_in_header(ExternalInboundMessageHeader {
        src: MsgAddressExt::default(),
        dst: address.clone(),
        import_fee: Default::default(),
    });
    msg.set_body(body);

    let msg_cell = msg
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize msg: {e}"))?;
    let boc = write_boc(&msg_cell).map_err(|e| anyhow::anyhow!("write BOC: {e}"))?;
    Ok(super::base64_encode(&boc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tvm_block::MsgAddrStd;
    use tvm_types::AccountId;

    fn test_address() -> MsgAddressInt {
        MsgAddressInt::AddrStd(MsgAddrStd::with_address(
            None,
            0,
            AccountId::from_raw(vec![0xABu8; 32], 256),
        ))
    }

    fn test_secret() -> String {
        hex::encode(SigningKey::generate(&mut rand::rngs::OsRng).to_bytes())
    }

    #[test]
    fn encode_submit_transaction_produces_boc() {
        let result = encode_submit_transaction(
            &test_address(),
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            1_000_000_000,
            true,
            &test_secret(),
        );
        assert!(result.is_ok(), "{:?}", result.err());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn encode_confirm_transaction_produces_boc() {
        assert!(encode_confirm_transaction(&test_address(), 12345, &test_secret()).is_ok());
    }

    #[test]
    fn encode_send_transaction_produces_boc() {
        let result = encode_send_transaction(
            &test_address(),
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            500_000_000,
            false,
            &test_secret(),
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn encode_submit_invalid_secret() {
        assert!(
            encode_submit_transaction(&test_address(), "0:abc", 100, true, "tooshort").is_err()
        );
    }

    #[test]
    fn different_calls_produce_different_bocs() {
        let addr = test_address();
        let secret = test_secret();
        let dest = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let b1 = encode_submit_transaction(&addr, dest, 100, true, &secret).unwrap();
        let b2 = encode_confirm_transaction(&addr, 1, &secret).unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn encode_external_call_rejects_short_address() {
        // Loading the contract isn't required to trigger the address-length
        // guard, since it fires before any signing work. Pass a minimal valid
        // ABI shell; the guard runs before any function lookup.
        let abi_json = r#"{
            "ABI version": 2, "version": "2.4", "header": [],
            "functions": [], "events": [], "fields": []
        }"#;
        let abi = tvm_abi::Contract::load(abi_json.as_bytes()).unwrap();
        let too_short = "0:abcdef";
        let result = encode_external_call(
            too_short,
            &abi,
            "deployWallet",
            &serde_json::json!({}),
            &"00".repeat(32),
        );
        let err = result.expect_err("must reject short address bytes, not panic");
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn encode_external_call_rejects_invalid_format() {
        let abi_json = r#"{
            "ABI version": 2, "version": "2.4", "header": [],
            "functions": [], "events": [], "fields": []
        }"#;
        let abi = tvm_abi::Contract::load(abi_json.as_bytes()).unwrap();
        let result = encode_external_call(
            "missing_colon",
            &abi,
            "deployWallet",
            &serde_json::json!({}),
            &"00".repeat(32),
        );
        assert!(result.is_err());
    }
}
