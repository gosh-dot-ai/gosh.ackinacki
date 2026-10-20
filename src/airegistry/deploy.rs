// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Deploy airegistry contracts via `tvm_client::encode_message`.
//!
//! `encode_message` with a `DeploySet` builds the stateInit (code from the TVC +
//! data from `initial_data`/the signer's pubkey) and returns BOTH the deploy
//! message and the **derived address** — so we don't hand-roll abi-2.4 init-data
//! or `tvm.hash(stateInit)`. The contract then self-registers with its parent at
//! exactly that address, which cross-checks the derivation on-chain.
//!
//! Static `varInit` per contract (mirrors the upstream airegistry tests):
//! - SuperRoot:        init_data `{}`              ctor `{pubkey, rootModelCode, manifestCode}`
//! - RootModel:        `{_ownerPubkey, _superRootAddress}`   ctor `{tokenContractCode}`
//! - ManifestMetadata: `{_ownerPubkey, _rootModelAddress, _superRootAddress}` ctor `{apiSchemaJson}`
//! - TokenContract:    `{_sellerPubkey, _rootModelAddress, _nonce}` ctor `{modelName, endpoint, ...}`

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::Value;
use tvm_client::abi::{encode_message, Abi, CallSet, DeploySet, ParamsOfEncodeMessage, Signer};
use tvm_client::crypto::KeyPair;
use tvm_client::{ClientConfig, ClientContext};

/// The signed deploy message and the address the contract will deploy at.
#[derive(Debug, Clone)]
pub struct DeployMessage {
    pub address: String,
    pub message_boc_b64: String,
}

/// Build a signed deploy message for an airegistry contract. `tvc` is the raw
/// TVC bytes; `init_data` is the static varInit JSON (`{}` for SuperRoot);
/// `ctor` is the constructor input JSON; the keypair signs the deploy.
pub async fn build_deploy(
    ctx: &Arc<ClientContext>,
    abi_json: &str,
    tvc: &[u8],
    init_data: Value,
    ctor: Value,
    public_hex: &str,
    secret_hex: &str,
) -> Result<DeployMessage> {
    use base64::Engine;
    let abi = Abi::Json(abi_json.to_string());

    // ABI 2.4 contracts mark the tvm pubkey (`_pubkey`) as an `init` storage
    // field that must be supplied in `initial_data` (initial_pubkey is ignored
    // for >= 2.4). Inject it from the signing keypair's public key.
    let mut init_obj = match init_data {
        Value::Object(m) => m,
        Value::Null => serde_json::Map::new(),
        other => {
            return Err(anyhow!("init_data must be a JSON object, got {other}"));
        }
    };
    init_obj
        .entry("_pubkey".to_string())
        .or_insert_with(|| Value::String(format!("0x{public_hex}")));
    let init_data = Value::Object(init_obj);

    let encoded = encode_message(
        ctx.clone(),
        ParamsOfEncodeMessage {
            abi,
            address: None,
            deploy_set: Some(DeploySet {
                tvc: Some(base64::engine::general_purpose::STANDARD.encode(tvc)),
                code: None,
                state_init: None,
                workchain_id: Some(0),
                initial_data: Some(init_data),
                initial_pubkey: None,
            }),
            call_set: Some(CallSet {
                function_name: "constructor".to_string(),
                header: None,
                input: Some(ctor),
            }),
            signer: Signer::Keys {
                keys: KeyPair {
                    public: public_hex.to_string(),
                    secret: secret_hex.to_string(),
                },
            },
            processing_try_index: None,
            // v3 CapSignatureWithId — see airegistry::calls::network_signature_id.
            signature_id: None,
        },
    )
    .await
    .map_err(|e| anyhow!("encode deploy message: {e}"))?;

    Ok(DeployMessage {
        address: encoded.address,
        message_boc_b64: encoded.message,
    })
}

/// Create a network-less tvm_client context for message encoding (local).
pub fn local_context() -> Result<Arc<ClientContext>> {
    Ok(Arc::new(
        ClientContext::new(ClientConfig::default())
            .map_err(|e| anyhow!("create tvm client context: {e}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airegistry::abi::Contract;

    #[tokio::test]
    async fn build_super_root_deploy_is_deterministic() {
        // Same keys + same tvc + same ctor ⇒ same derived address.
        let ctx = local_context().unwrap();
        let pubk = "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c";
        let seck = "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b";
        let tvc = Contract::SuperRoot.tvc();
        let ctor = serde_json::json!({
            "pubkey": format!("0x{pubk}"),
            "rootModelCode": Contract::RootModel.code_boc_b64().unwrap(),
            "manifestCode": Contract::ManifestMetadata.code_boc_b64().unwrap(),
        });
        let a = build_deploy(
            &ctx,
            Contract::SuperRoot.abi_json(),
            tvc,
            serde_json::json!({}),
            ctor.clone(),
            pubk,
            seck,
        )
        .await;
        let b = build_deploy(
            &ctx,
            Contract::SuperRoot.abi_json(),
            tvc,
            serde_json::json!({}),
            ctor,
            pubk,
            seck,
        )
        .await;
        // Both either succeed with identical addresses, or fail identically — but
        // a valid encode must produce a stable address.
        if let (Ok(a), Ok(b)) = (&a, &b) {
            assert_eq!(a.address, b.address, "deploy address must be deterministic");
            assert!(a.address.starts_with("0:"));
        } else {
            panic!("encode_message failed: a={:?} b={:?}", a.err(), b.err());
        }
    }

    /// §12.1 known-good derivation vector: a TokenContract deployed with fixed
    /// keys / nonce / RootModel must derive to a pinned address (the same value
    /// `RootModel.getTokenContractAddress` returns on-chain — cross-checked live
    /// in the E2E). Guards the off-chain derivation against ABI/TVC drift.
    #[tokio::test]
    async fn token_contract_derivation_golden_vector() {
        let ctx = local_context().unwrap();
        let pubk = "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c";
        let seck = "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b";
        let rm = "0:2222222222222222222222222222222222222222222222222222222222222222";
        let msg = build_deploy(
            &ctx,
            Contract::TokenContract.abi_json(),
            Contract::TokenContract.tvc(),
            serde_json::json!({ "_sellerPubkey": format!("0x{pubk}"), "_rootModelAddress": rm, "_nonce": "1" }),
            serde_json::json!({ "modelName": "GPT-X", "endpoint": "https://api.example.com", "totalTokensForSale": "10", "tickSize": "1", "burnFeeBps": 0, "maxReservedSessions": 3 }),
            pubk,
            seck,
        )
        .await
        .expect("build TokenContract deploy");
        assert_eq!(
            msg.address, "0:39e68432167e7ab422f1fef526ba0c12732dcbbf4b358d427506787379294e2a",
            "TokenContract derivation drifted from the known-good vector"
        );
    }
}
