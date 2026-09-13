// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Deploy UpdateCustodianMultisigWallet (2-of-3 for agent swarm).

use anyhow::{bail, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tvm_abi::token::Tokenizer;
use tvm_block::{
    Deserializable, ExternalInboundMessageHeader, Message, MsgAddressExt, MsgAddressInt,
    Serializable, StateInit,
};
use tvm_types::{ed25519_create_private_key, write_boc, AccountId, SliceData};

use super::contracts::{MULTISIG_ABI, MULTISIG_TVC};

/// Parameters for deploying a 2-of-3 multisig wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployParams {
    pub agent_pubkey: String,
    pub controller_pubkey: String,
    pub owner_pubkey: String,
    pub initial_value: u64,
}

/// Result of preparing a deploy message.
#[derive(Debug)]
pub struct PreparedDeploy {
    pub address: String,
    pub message_boc_base64: String,
    pub address_int: MsgAddressInt,
}

/// Prepare a deploy message for a 2-of-3 multisig wallet.
pub fn prepare_deploy(params: &DeployParams, signer_secret: &str) -> Result<PreparedDeploy> {
    let agent_pubkey = parse_pubkey_u256(&params.agent_pubkey)?;
    let controller_pubkey = parse_pubkey_u256(&params.controller_pubkey)?;
    let owner_pubkey = parse_pubkey_u256(&params.owner_pubkey)?;
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

    let tvc_cell = tvm_types::read_single_root_boc(MULTISIG_TVC)
        .map_err(|e| anyhow::anyhow!("read TVC: {e}"))?;
    let mut state_init = StateInit::construct_from_cell(tvc_cell)
        .map_err(|e| anyhow::anyhow!("parse StateInit: {e}"))?;

    set_pubkey_in_data(&mut state_init, &signer_key)?;

    let state_init_cell = state_init
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize StateInit: {e}"))?;
    let address =
        MsgAddressInt::with_standart(None, 0, AccountId::from(state_init_cell.repr_hash()))
            .map_err(|e| anyhow::anyhow!("address: {e}"))?;

    let address_str = format!("0:{}", hex::encode(state_init_cell.repr_hash().as_slice()));

    let abi = &*MULTISIG_ABI;
    let constructor = abi
        .function("constructor")
        .map_err(|e| anyhow::anyhow!("constructor not found: {e}"))?;

    let constructor_params = serde_json::json!({
        "owners_pubkey": [agent_pubkey, controller_pubkey, owner_pubkey],
        "owners_address": [],
        "reqConfirms": 2,
        "reqConfirmsData": 2,
        "value": params.initial_value.to_string(),
    });

    let header = super::build_header(&signer_key);
    let header_tokens = Tokenizer::tokenize_optional_params(constructor.header_params(), &header)
        .map_err(|e| anyhow::anyhow!("header tokenize: {e}"))?;
    let input_tokens =
        Tokenizer::tokenize_all_params(constructor.input_params(), &constructor_params)
            .map_err(|e| anyhow::anyhow!("input tokenize: {e}"))?;

    let sign_key =
        ed25519_create_private_key(&signer_bytes).map_err(|e| anyhow::anyhow!("privkey: {e}"))?;
    let body_builder = constructor
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
    msg.set_state_init(state_init);
    msg.set_body(body);

    let msg_cell = msg
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize msg: {e}"))?;
    let boc = write_boc(&msg_cell).map_err(|e| anyhow::anyhow!("write BOC: {e}"))?;

    Ok(PreparedDeploy {
        address: address_str,
        message_boc_base64: super::base64_encode(&boc),
        address_int: address,
    })
}

fn parse_pubkey_u256(hex_str: &str) -> Result<String> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        bail!("public key must be 32 bytes, got {}", bytes.len());
    }
    Ok(format!("0x{hex_str}"))
}

fn set_pubkey_in_data(state_init: &mut StateInit, key: &SigningKey) -> Result<()> {
    let pubkey_bytes = key.verifying_key().to_bytes();
    let data = state_init.data.clone().unwrap_or_default();
    let mut data_slice =
        SliceData::load_cell(data).map_err(|e| anyhow::anyhow!("load data: {e}"))?;

    let mut builder = tvm_types::BuilderData::new();
    builder
        .append_raw(&pubkey_bytes, 256)
        .map_err(|e| anyhow::anyhow!("append pubkey: {e}"))?;

    if data_slice.remaining_bits() >= 256 {
        data_slice
            .get_next_bits(256)
            .map_err(|e| anyhow::anyhow!("skip old pubkey: {e}"))?;
    }
    if data_slice.remaining_bits() > 0 || data_slice.remaining_references() > 0 {
        builder
            .checked_append_references_and_data(&data_slice)
            .map_err(|e| anyhow::anyhow!("append rest: {e}"))?;
    }

    state_init.set_data(
        builder
            .into_cell()
            .map_err(|e| anyhow::anyhow!("build cell: {e}"))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> DeployParams {
        let k1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let k2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let k3 = SigningKey::generate(&mut rand::rngs::OsRng);
        DeployParams {
            agent_pubkey: hex::encode(k1.verifying_key().as_bytes()),
            controller_pubkey: hex::encode(k2.verifying_key().as_bytes()),
            owner_pubkey: hex::encode(k3.verifying_key().as_bytes()),
            initial_value: 1_000_000_000,
        }
    }

    #[test]
    fn prepare_deploy_produces_valid_boc() {
        let params = test_params();
        let signer = SigningKey::generate(&mut rand::rngs::OsRng);
        let result = prepare_deploy(&params, &hex::encode(signer.to_bytes()));
        assert!(result.is_ok(), "deploy failed: {:?}", result.err());
        let deploy = result.unwrap();
        assert!(deploy.address.starts_with("0:"));
        assert!(!deploy.message_boc_base64.is_empty());
    }

    #[test]
    fn prepare_deploy_different_keys_different_addresses() {
        let p1 = test_params();
        let p2 = test_params();
        let s1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let s2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let d1 = prepare_deploy(&p1, &hex::encode(s1.to_bytes())).unwrap();
        let d2 = prepare_deploy(&p2, &hex::encode(s2.to_bytes())).unwrap();
        assert_ne!(d1.address, d2.address);
    }

    #[test]
    fn prepare_deploy_invalid_secret_length() {
        let result = prepare_deploy(&test_params(), "aabb");
        assert!(result.is_err());
    }

    #[test]
    fn prepare_deploy_invalid_pubkey() {
        let mut params = test_params();
        params.agent_pubkey = "not_hex".into();
        let s = SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(prepare_deploy(&params, &hex::encode(s.to_bytes())).is_err());
    }

    #[test]
    fn parse_pubkey_u256_valid() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let r = parse_pubkey_u256(&hex::encode(key.verifying_key().as_bytes()));
        assert!(r.is_ok());
        assert!(r.unwrap().starts_with("0x"));
    }

    #[test]
    fn parse_pubkey_u256_wrong_length() {
        let r = parse_pubkey_u256("aabb");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("32 bytes"));
    }
}
