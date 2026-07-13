// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Multisig-flow voucher minting: route `RootPN.generateVoucher` through a
//! user-owned multisig wallet's `sendTransaction`, capture the resulting
//! `VoucherGenerated` ext-out by `skUCommit` match, and run the halo2 prover.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::airegistry::calls::{encode_external_call, encode_internal_payload};
use crate::airegistry::deploy::local_context;
use crate::private_note::artifacts::ROOT_PN_ABI_JSON;
use crate::private_note::halo2::live::{
    prove_voucher_for_event, Halo2Proof, ProveVoucherForEventParams,
};
use crate::private_note::halo2::paths::Halo2Paths;
use crate::private_note::halo2::sk_commit::compute_sk_u_commit_hex;
use crate::private_note::proof;
use crate::private_note::voucher_event;
use crate::sdk::{Address, KeyPair};
use crate::wallet::query::send_message_routed;

/// Native vmshell value attached to the multisig -> RootPN internal message.
const SUBMIT_NATIVE_VALUE: u128 = 2_000_000_000;

/// How long to wait for the indexer to surface our `VoucherGenerated` event.
const VOUCHER_EVENT_RESOLVE_TIMEOUT_S: u64 = 480;

/// ackinacki-kit v2.1.0 user/dashboard multisig.
const GENERIC_MULTISIG_CODE_HASH: &str =
    "3a7a53248ff39fde936a4274eab143b5fac94feac0d8e2e2748aac5e74538d5f";

/// Historical gosh.ackinacki operational multisig.
const UPDATE_CUSTODIAN_MULTISIG_CODE_HASH: &str =
    "8470e1da28a2b4c742b5f7edefdd97db81c79e726f8a8b0be78d921adaf32414";

/// Generic ackinacki-kit `Multisig`. Its `sendTransaction` ABI includes the
/// trailing destination `dapp_id` argument.
const GENERIC_MULTISIG_ABI_JSON: &str = r#"{
  "ABI version": 2,
  "version": "2.4",
  "header": ["pubkey", "time", "expire"],
  "functions": [
    {
      "name": "sendTransaction",
      "inputs": [
        { "name": "dest", "type": "address" },
        { "name": "value", "type": "uint128" },
        { "name": "cc", "type": "map(uint32,varuint32)" },
        { "name": "bounce", "type": "bool" },
        { "name": "flags", "type": "uint8" },
        { "name": "payload", "type": "cell" },
        { "name": "dapp_id", "type": "uint256" }
      ],
      "outputs": [{ "name": "value0", "type": "address" }]
    }
  ],
  "events": [],
  "data": []
}"#;

/// Historical `UpdateCustodianMultisigWallet`. Its `sendTransaction` ABI has no
/// trailing `dapp_id` argument.
const UPDATE_CUSTODIAN_MULTISIG_ABI_JSON: &str = r#"{
  "ABI version": 2,
  "version": "2.4",
  "header": ["pubkey", "time", "expire"],
  "functions": [
    {
      "name": "sendTransaction",
      "inputs": [
        { "name": "dest", "type": "address" },
        { "name": "value", "type": "uint128" },
        { "name": "cc", "type": "map(uint32,varuint32)" },
        { "name": "bounce", "type": "bool" },
        { "name": "flags", "type": "uint8" },
        { "name": "payload", "type": "cell" }
      ],
      "outputs": [{ "name": "value0", "type": "address" }]
    }
  ],
  "events": [],
  "data": []
}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultisigForwardKind {
    Generic,
    UpdateCustodian,
}

impl MultisigForwardKind {
    fn from_code_hash(code_hash: &str) -> Result<Self> {
        let code_hash = code_hash
            .trim()
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        match code_hash.as_str() {
            GENERIC_MULTISIG_CODE_HASH => Ok(Self::Generic),
            UPDATE_CUSTODIAN_MULTISIG_CODE_HASH => Ok(Self::UpdateCustodian),
            other => Err(anyhow!(
                "unsupported funding wallet code_hash {other}; supported generic Multisig \
                 {GENERIC_MULTISIG_CODE_HASH} and UpdateCustodianMultisigWallet \
                 {UPDATE_CUSTODIAN_MULTISIG_CODE_HASH}"
            )),
        }
    }

    fn abi_json(self) -> &'static str {
        match self {
            Self::Generic => GENERIC_MULTISIG_ABI_JSON,
            Self::UpdateCustodian => UPDATE_CUSTODIAN_MULTISIG_ABI_JSON,
        }
    }

    /// Build the wallet's `sendTransaction` params. For the generic Multisig the
    /// trailing `dapp_id` is the DApp of the destination (`root_pn`) — supplied by
    /// the caller, since this library does not know any specific RootPN deployment.
    fn send_transaction_params(
        self,
        root_pn: &Address,
        forward_dapp_id: &str,
        cc: serde_json::Map<String, Value>,
        voucher_body: String,
    ) -> Value {
        let mut params = json!({
            "dest": root_pn.with_workchain(),
            "value": SUBMIT_NATIVE_VALUE.to_string(),
            "cc": Value::Object(cc),
            "bounce": true,
            "flags": 1,
            "payload": voucher_body,
        });
        if self == Self::Generic {
            params["dapp_id"] = Value::String(forward_dapp_id.to_string());
        }
        params
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn mint_voucher_via_multisig(
    endpoint: &str,
    root_pn: &Address,
    forward_dapp_id: &str,
    multisig_address: &Address,
    multisig_owner_keys: &KeyPair,
    recipient_ephemeral_pubkey_hex: &str,
    voucher_token_type: u32,
    voucher_value: u64,
    is_fee: bool,
    paths: &Halo2Paths,
) -> Result<Halo2Proof> {
    let recipient_ephemeral_pubkey_hex =
        proof::strip_0x(recipient_ephemeral_pubkey_hex).to_string();

    // 1. Random sk_u; skUCommit = poseidon([sk_u, 0]).
    let sk_u_hex = proof::random_secret_key();
    let sk_u_commit_hex = compute_sk_u_commit_hex(&sk_u_hex)
        .map_err(|e| anyhow!("compute skUCommit (poseidon([sk_u, 0])): {e}"))?;

    // 2. Encode the `RootPN.generateVoucher` body.
    let ctx = local_context()?;
    let voucher_body = encode_internal_payload(
        &ctx,
        ROOT_PN_ABI_JSON,
        "generateVoucher",
        json!({
            "skUCommit": format!("0x{sk_u_commit_hex}"),
            "isFee": is_fee,
        }),
    )
    .await
    .map_err(|e| anyhow!("encode RootPN.generateVoucher body: {e}"))?;

    // 3. Drive the multisig's direct sendTransaction with ECC attached.
    let mut cc = serde_json::Map::new();
    cc.insert(
        voucher_token_type.to_string(),
        Value::String(voucher_value.to_string()),
    );
    let http = reqwest::Client::new();
    let wallet_code_hash = fetch_wallet_code_hash(&http, endpoint, multisig_address).await?;
    let forward_kind = MultisigForwardKind::from_code_hash(&wallet_code_hash)?;
    let boc = encode_external_call(
        &ctx,
        forward_kind.abi_json(),
        &multisig_address.with_workchain(),
        "sendTransaction",
        forward_kind.send_transaction_params(root_pn, forward_dapp_id, cc, voucher_body),
        multisig_owner_keys.public_hex(),
        multisig_owner_keys.secret_hex(),
    )
    .await
    .map_err(|e| anyhow!("encode Multisig.sendTransaction -> RootPN.generateVoucher: {e}"))?;

    send_message_routed(
        &http,
        endpoint,
        &boc,
        multisig_address.bare(),
        multisig_address.bare(),
        None,
    )
    .await
    .map_err(|e| anyhow!("submit Multisig.sendTransaction -> RootPN.generateVoucher: {e}"))?;

    // 4. Locate OUR voucher event by `skUCommit`.
    let event = voucher_event::wait_for_voucher_event_by_sk_u_commit(
        &http,
        endpoint,
        root_pn,
        &format!("0x{sk_u_commit_hex}"),
        Duration::from_secs(VOUCHER_EVENT_RESOLVE_TIMEOUT_S),
    )
    .await
    .map_err(|e| anyhow!("wait_for_voucher_event_by_sk_u_commit (multisig flow): {e}"))?;

    // 5. Hand off to the production Stage B prover.
    prove_voucher_for_event(ProveVoucherForEventParams {
        endpoint: endpoint.to_string(),
        event,
        sk_u_hex,
        sk_u_commit_hex,
        voucher_value,
        voucher_token_type,
        ephemeral_pubkey_hex: recipient_ephemeral_pubkey_hex,
        history_proof_window_size: None,
        paths,
    })
    .await
}

async fn fetch_wallet_code_hash(
    http: &reqwest::Client,
    endpoint: &str,
    wallet: &Address,
) -> Result<String> {
    let bare = wallet.bare();
    let query = format!(
        "{{ blockchain {{ account(account_id: \"{bare}\", dapp_id: \"{bare}\") {{ info {{ acc_type_name code_hash }} }} }} }}"
    );
    let url = format!("{}/graphql", endpoint.trim_end_matches('/'));
    let resp: Value = http
        .post(url)
        .json(&json!({ "query": query }))
        .send()
        .await
        .map_err(|e| anyhow!("read funding wallet code_hash: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("read funding wallet code_hash: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("decode funding wallet code_hash response: {e}"))?;
    if let Some(errors) = resp.get("errors") {
        return Err(anyhow!(
            "read funding wallet code_hash GraphQL errors: {errors}"
        ));
    }
    let info = resp
        .pointer("/data/blockchain/account/info")
        .ok_or_else(|| anyhow!("funding wallet {} not found", wallet.with_workchain()))?;
    let acc_type = info
        .get("acc_type_name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if acc_type != "Active" {
        return Err(anyhow!(
            "funding wallet {} is not Active (acc_type={acc_type})",
            wallet.with_workchain()
        ));
    }
    info.get("code_hash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "funding wallet {} has no code_hash",
                wallet.with_workchain()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_voucher_body_encodes() {
        let ctx = local_context().unwrap();
        let body = encode_internal_payload(
            &ctx,
            ROOT_PN_ABI_JSON,
            "generateVoucher",
            json!({
                "skUCommit": "0x1234",
                "isFee": false,
            }),
        )
        .await
        .expect("encode generateVoucher");
        assert!(!body.is_empty());
    }

    #[test]
    fn classifies_supported_wallet_hashes() {
        assert_eq!(
            MultisigForwardKind::from_code_hash(GENERIC_MULTISIG_CODE_HASH).unwrap(),
            MultisigForwardKind::Generic
        );
        assert_eq!(
            MultisigForwardKind::from_code_hash(UPDATE_CUSTODIAN_MULTISIG_CODE_HASH).unwrap(),
            MultisigForwardKind::UpdateCustodian
        );
        let err = MultisigForwardKind::from_code_hash("00").unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported funding wallet code_hash"));
    }

    #[test]
    fn generic_multisig_forward_uses_caller_supplied_dapp_id() {
        let root_pn =
            Address::parse("0:1010101010101010101010101010101010101010101010101010101010101010")
                .unwrap();
        // A non-zero value proves the dapp_id is caller-supplied, not hardcoded.
        let params = MultisigForwardKind::Generic.send_transaction_params(
            &root_pn,
            "7",
            serde_json::Map::new(),
            "payload".to_string(),
        );
        assert_eq!(params["dapp_id"], "7");

        // The custodian 6-arg forward has no dapp_id field at all.
        let legacy = MultisigForwardKind::UpdateCustodian.send_transaction_params(
            &root_pn,
            "7",
            serde_json::Map::new(),
            "payload".to_string(),
        );
        assert!(legacy.get("dapp_id").is_none());
    }

    #[test]
    fn generic_multisig_abi_has_trailing_dapp_id() {
        let abi: Value = serde_json::from_str(GENERIC_MULTISIG_ABI_JSON).unwrap();
        let inputs = abi["functions"][0]["inputs"].as_array().unwrap();
        let last = inputs.last().unwrap();
        assert_eq!(last["name"], "dapp_id");
        assert_eq!(last["type"], "uint256");
    }
}
