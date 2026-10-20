// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Encode airegistry runtime calls via `tvm_client` — the same proven path as
//! [`crate::airegistry::deploy`].
//!
//! Two shapes:
//!   * [`encode_external_call`] — a signed external-inbound message to any
//!     contract whose ABI carries a `pubkey` header. Used for seller-authorised
//!     TokenContract calls (`consumeSession`, `withdrawShell`) and for the
//!     consumer wallet's `submitTransaction`.
//!   * [`encode_internal_payload`] — an *unsigned* internal message body cell,
//!     handed to the multisig as the `payload` so the wallet forwards a
//!     `buyTokens()` / `cancel()` call (with ECC[2] SHELL attached via `cc`
//!     for buyTokens) to the TokenContract.
//!
//! The consumer never calls the TokenContract directly: `buyTokens` reads
//! `msg.currencies[SHELL_ECC_ID]` and `cancel` checks
//! `msg.sender == _currentBuyer`, so both must arrive as *internal* messages
//! from the buyer's wallet. [`wallet_forward`] assembles that submitTransaction.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tvm_client::abi::{
    encode_message, encode_message_body, Abi, CallSet, ParamsOfEncodeMessage,
    ParamsOfEncodeMessageBody, Signer,
};
use tvm_client::crypto::KeyPair;
use tvm_client::ClientContext;

/// SHELL extra-currency id (ECC[2]) — the token TokenContract prices in.
pub const SHELL_ECC_ID: u32 = 2;

/// Encode a signed external-inbound call to `address`. Returns the message BOC
/// (base64). `abi_json` must declare a `pubkey` header (all airegistry +
/// multisig ABIs do).
pub async fn encode_external_call(
    ctx: &Arc<ClientContext>,
    abi_json: &str,
    address: &str,
    function: &str,
    input: Value,
    public_hex: &str,
    secret_hex: &str,
) -> Result<String> {
    let signature_id = network_signature_id(ctx).await;
    let encoded = encode_message(
        ctx.clone(),
        ParamsOfEncodeMessage {
            abi: Abi::Json(abi_json.to_string()),
            address: Some(address.to_string()),
            deploy_set: None,
            call_set: Some(CallSet {
                function_name: function.to_string(),
                header: None,
                input: Some(input),
            }),
            signer: Signer::Keys {
                keys: KeyPair {
                    public: public_hex.to_string(),
                    secret: secret_hex.to_string(),
                },
            },
            processing_try_index: None,
            // Acki Nacki v3 can enable CapSignatureWithId, where external
            // messages must be signed WITH the network global_id. The SDK
            // exposes that as `signature_id`; None is correct only when the
            // network config has no signature id.
            signature_id,
        },
    )
    .await
    .map_err(|e| anyhow!("encode external call {function}: {e}"))?;
    Ok(encoded.message)
}

/// The network's signature id (`global_id` when `CapSignatureWithId` is set,
/// else `None`) — required to sign external messages on Acki Nacki v3. The v3
/// SDK serves it locally from a hardcoded config, so this is a cheap call.
pub async fn network_signature_id(ctx: &Arc<ClientContext>) -> Option<i32> {
    tvm_client::net::get_signature_id(ctx.clone())
        .await
        .ok()
        .and_then(|r| r.signature_id)
}

/// Encode an unsigned INTERNAL message body for `function` — the `payload` cell
/// the multisig forwards. Returns the body BOC (base64).
pub async fn encode_internal_payload(
    ctx: &Arc<ClientContext>,
    abi_json: &str,
    function: &str,
    input: Value,
) -> Result<String> {
    let res = encode_message_body(
        ctx.clone(),
        ParamsOfEncodeMessageBody {
            abi: Abi::Json(abi_json.to_string()),
            call_set: CallSet {
                function_name: function.to_string(),
                header: None,
                input: Some(input),
            },
            is_internal: true,
            signer: Signer::None,
            processing_try_index: None,
            address: None,
            signature_id: None,
        },
    )
    .await
    .map_err(|e| anyhow!("encode internal payload {function}: {e}"))?;
    Ok(res.body)
}

/// Build a multisig `submitTransaction` that forwards `payload_b64` (an encoded
/// inner-call body) to `dest`, attaching `shell_ecc` units of ECC[2] SHELL.
/// `value_vmshell` is native VMSHELL for forward gas. On a 1-of-1 operational
/// wallet (reqConfirms==1) submitTransaction executes immediately.
///
/// `multisig_abi_json` is the consumer wallet ABI; the call is signed by the
/// wallet custodian keypair.
#[allow(clippy::too_many_arguments)]
pub async fn wallet_forward(
    ctx: &Arc<ClientContext>,
    multisig_abi_json: &str,
    wallet_address: &str,
    dest: &str,
    value_vmshell: u128,
    shell_ecc: u128,
    bounce: bool,
    payload_b64: &str,
    public_hex: &str,
    secret_hex: &str,
) -> Result<String> {
    let mut cc = serde_json::Map::new();
    if shell_ecc > 0 {
        cc.insert(SHELL_ECC_ID.to_string(), json!(shell_ecc.to_string()));
    }
    encode_external_call(
        ctx,
        multisig_abi_json,
        wallet_address,
        "submitTransaction",
        json!({
            "dest": dest,
            "value": value_vmshell.to_string(),
            "cc": Value::Object(cc),
            "bounce": bounce,
            "flag": 1,
            "payload": payload_b64,
        }),
        public_hex,
        secret_hex,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airegistry::abi::Contract;
    use crate::airegistry::deploy::local_context;

    #[tokio::test]
    async fn internal_payload_buytokens_encodes() {
        let ctx = local_context().unwrap();
        // buyTokens() has no inputs — a stable, non-empty body cell.
        let body = encode_internal_payload(
            &ctx,
            Contract::TokenContract.abi_json(),
            "buyTokens",
            json!({}),
        )
        .await
        .expect("encode buyTokens payload");
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn internal_payload_cancel_encodes() {
        let ctx = local_context().unwrap();
        // cancel(payoutAddress) is the buyer's stop-loss in the new (no
        // buyer-confirm) flow — refunds the unconsumed reservation.
        let body = encode_internal_payload(
            &ctx,
            Contract::TokenContract.abi_json(),
            "cancel",
            json!({ "payoutAddress": "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" }),
        )
        .await
        .expect("encode cancel payload");
        assert!(!body.is_empty());
    }

    /// §12.1 golden BOC: the internal-message bodies the wallet forwards must be
    /// byte-stable (a regression guard on the ABI/encoder). The buyTokens golden
    /// matches the real on-chain forward body observed on shellnet.
    #[tokio::test]
    async fn internal_payload_golden_bocs() {
        let ctx = local_context().unwrap();
        let buy = encode_internal_payload(
            &ctx,
            Contract::TokenContract.abi_json(),
            "buyTokens",
            json!({}),
        )
        .await
        .unwrap();
        assert_eq!(
            buy, "te6ccgEBAQEABgAACF5KEFM=",
            "buyTokens() body BOC drifted"
        );
    }

    #[tokio::test]
    async fn wallet_forward_buildable_with_ecc() {
        let ctx = local_context().unwrap();
        let pubk = "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c";
        let seck = "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b";
        let payload = encode_internal_payload(
            &ctx,
            Contract::TokenContract.abi_json(),
            "buyTokens",
            json!({}),
        )
        .await
        .unwrap();
        let msg = wallet_forward(
            &ctx,
            crate::wallet::contracts::MULTISIG_ABI_JSON,
            "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "0:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            1_000_000_000,
            6,
            false,
            &payload,
            pubk,
            seck,
        )
        .await
        .expect("build wallet_forward submitTransaction");
        assert!(!msg.is_empty());
    }
}
