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
use crate::wallet::multisig::MultisigKind;
use crate::wallet::query::send_message_routed;

/// Native vmshell value attached to the multisig -> RootPN internal message.
const SUBMIT_NATIVE_VALUE: u128 = 2_000_000_000;

/// How long to wait for the indexer to surface our `VoucherGenerated` event.
const VOUCHER_EVENT_RESOLVE_TIMEOUT_S: u64 = 480;

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

    // 3. Drive the multisig's forward call with the voucher's ECC attached. The
    //    ATTACHED amount is the wire value (deposit = nominal + GAS_DEPOSIT; gas =
    //    raw) — RootPN.generateVoucher deducts GAS_DEPOSIT and emits the nominal.
    let mut cc = serde_json::Map::new();
    cc.insert(
        voucher_token_type.to_string(),
        Value::String(proof::voucher_wire_raw(is_fee, voucher_value).to_string()),
    );
    let http = reqwest::Client::new();
    let wallet_code_hash = fetch_wallet_code_hash(&http, endpoint, multisig_address).await?;
    let forward_kind = MultisigKind::from_code_hash(&wallet_code_hash)?;
    let (forward_method, forward_params) = forward_kind.forward_call(
        &root_pn.with_workchain(),
        forward_dapp_id,
        cc,
        SUBMIT_NATIVE_VALUE,
        voucher_body,
    );
    let boc = encode_external_call(
        &ctx,
        forward_kind.abi_json(),
        &multisig_address.with_workchain(),
        forward_method,
        forward_params,
        multisig_owner_keys.public_hex(),
        multisig_owner_keys.secret_hex(),
    )
    .await
    .map_err(|e| anyhow!("encode Multisig.{forward_method} -> RootPN.generateVoucher: {e}"))?;

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
    fn funding_path_accepts_every_registry_wallet_incl_v2() {
        // The forward path resolves the funding wallet through the shared
        // registry, so it now accepts UpdateCustodianMultisigWallet_v2 (09f596d5)
        // as well as v1 and the generic Multisig. (Classification and the exact
        // send-shape are unit-tested in `wallet::multisig`.)
        for kind in [
            MultisigKind::Generic,
            MultisigKind::UpdateCustodianV1,
            MultisigKind::UpdateCustodianV2,
        ] {
            assert_eq!(
                MultisigKind::from_code_hash(kind.code_hash()).unwrap(),
                kind
            );
        }
        // v2 forwards via submitTransaction with the caller-supplied dapp_id;
        // v1 via sendTransaction with no dapp_id.
        let (m2, v2) = MultisigKind::UpdateCustodianV2.forward_call(
            "0:aa",
            "4",
            serde_json::Map::new(),
            SUBMIT_NATIVE_VALUE,
            "payload".to_string(),
        );
        assert_eq!(m2, "submitTransaction");
        assert_eq!(v2["dapp_id"], "4");
        let (m1, v1) = MultisigKind::UpdateCustodianV1.forward_call(
            "0:aa",
            "4",
            serde_json::Map::new(),
            SUBMIT_NATIVE_VALUE,
            "payload".to_string(),
        );
        assert_eq!(m1, "sendTransaction");
        assert!(v1.get("dapp_id").is_none());
    }
}
