// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Multisig-flow voucher minting: route `RootPN.generateVoucher` through a
//! user-owned multisig wallet's `sendTransaction`, capture the resulting
//! `VoucherGenerated` ext-out by `skUCommit` match, and run the halo2 prover.

use std::time::Duration;

use serde_json::{json, Value};

use crate::airegistry::calls::{encode_external_call, encode_internal_payload};
use crate::airegistry::deploy::local_context;
use crate::private_note::artifacts::{ROOT_PN_ABI_JSON, ROOT_PN_ADDRESS};
use crate::private_note::halo2::live::{
    prove_voucher_for_event, Halo2Proof, ProveVoucherForEventParams,
};
use crate::private_note::halo2::paths::{Halo2Paths, Halo2PathsError};
use crate::private_note::halo2::sk_commit::compute_sk_u_commit_hex;
use crate::private_note::proof;
use crate::private_note::voucher_event;
use crate::sdk::{Address, KeyPair};
use crate::wallet::query::send_message_routed;

/// Native vmshell value attached to the multisig -> RootPN internal message.
const SUBMIT_NATIVE_VALUE: u128 = 2_000_000_000;

/// How long to wait for the indexer to surface our `VoucherGenerated` event.
const VOUCHER_EVENT_RESOLVE_TIMEOUT_S: u64 = 480;

/// The operational wallets deployed by dexdo/gosh.ackinacki are
/// `UpdateCustodianMultisigWallet` contracts. Their `sendTransaction` ABI does
/// not include the generic SDK multisig's trailing `dapp_id` argument.
const OPERATIONAL_MULTISIG_ABI_JSON: &str = r#"{
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

#[allow(clippy::too_many_arguments)]
pub async fn mint_voucher_via_multisig(
    endpoint: &str,
    multisig_address: &Address,
    multisig_owner_keys: &KeyPair,
    recipient_ephemeral_pubkey_hex: &str,
    voucher_token_type: u32,
    voucher_value: u64,
    is_fee: bool,
    paths: &Halo2Paths,
) -> std::result::Result<Halo2Proof, Halo2PathsError> {
    let root_pn = Address::parse(ROOT_PN_ADDRESS).expect("static RootPN address");
    let recipient_ephemeral_pubkey_hex =
        proof::strip_0x(recipient_ephemeral_pubkey_hex).to_string();

    // 1. Random sk_u; skUCommit = poseidon([sk_u, 0]).
    let sk_u_hex = proof::random_secret_key();
    let sk_u_commit_hex =
        compute_sk_u_commit_hex(&sk_u_hex).expect("compute skUCommit (poseidon([sk_u, 0]))");

    // 2. Encode the `RootPN.generateVoucher` body.
    let ctx = local_context().expect("create local tvm client context");
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
    .expect("encode RootPN.generateVoucher body");

    // 3. Drive the multisig's direct sendTransaction with ECC attached.
    let mut cc = serde_json::Map::new();
    cc.insert(
        voucher_token_type.to_string(),
        Value::String(voucher_value.to_string()),
    );
    let boc = encode_external_call(
        &ctx,
        OPERATIONAL_MULTISIG_ABI_JSON,
        &multisig_address.with_workchain(),
        "sendTransaction",
        json!({
            "dest": root_pn.with_workchain(),
            "value": SUBMIT_NATIVE_VALUE.to_string(),
            "cc": Value::Object(cc),
            "bounce": true,
            "flags": 1,
            "payload": voucher_body,
        }),
        multisig_owner_keys.public_hex(),
        multisig_owner_keys.secret_hex(),
    )
    .await
    .expect("encode Multisig.sendTransaction -> RootPN.generateVoucher");

    let http = reqwest::Client::new();
    send_message_routed(
        &http,
        endpoint,
        &boc,
        multisig_address.bare(),
        multisig_address.bare(),
        None,
    )
    .await
    .expect("submit Multisig.sendTransaction -> RootPN.generateVoucher");

    // 4. Locate OUR voucher event by `skUCommit`.
    let event = voucher_event::wait_for_voucher_event_by_sk_u_commit(
        &http,
        endpoint,
        &root_pn,
        &format!("0x{sk_u_commit_hex}"),
        Duration::from_secs(VOUCHER_EVENT_RESOLVE_TIMEOUT_S),
    )
    .await
    .expect("wait_for_voucher_event_by_sk_u_commit (multisig flow)");

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
}
