// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Shellnet Giver funding client (testnet only).
//!
//! The Giver at `0:1111…` mints free testnet SHELL/VMSHELL. We use it to fund
//! deploy addresses and wallets in the airegistry E2E. Disabled on mainnet.
//! Mirrors the upstream `tests/helper/common.py::send_from_giver`, which funds
//! an uninit deploy address with two `sendCurrencyWithFlag` calls (flag 16 then
//! flag 2).
//!
//! The GiverV3 ABI header is `["time", "expire"]` (no `pubkey` header param), so
//! we encode its calls via `tvm_client::encode_message` (which respects the
//! ABI's header) rather than the multisig-shaped `encode_external_call`.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tvm_client::abi::{encode_message, Abi, CallSet, ParamsOfEncodeMessage, Signer};
use tvm_client::crypto::KeyPair;
use tvm_client::ClientContext;

use super::contracts::GIVER_ABI_JSON;

/// Shellnet Giver funding client (testnet only).
pub struct GiverClient {
    ctx: Arc<ClientContext>,
    address: String,
    keys: KeyPair,
    endpoint: String,
    http: reqwest::Client,
}

impl GiverClient {
    pub fn new(
        ctx: Arc<ClientContext>,
        address: &str,
        public_hex: &str,
        secret_hex: &str,
        endpoint: &str,
        http: reqwest::Client,
    ) -> Self {
        Self {
            ctx,
            address: address.to_string(),
            keys: KeyPair {
                public: public_hex.to_string(),
                secret: secret_hex.to_string(),
            },
            endpoint: endpoint.to_string(),
            http,
        }
    }

    /// Fund an (uninit) deploy address with ECC[2] SHELL, mirroring upstream
    /// `send_from_giver`: `sendCurrencyWithFlag(flag=16)` then `(flag=2)`.
    pub async fn fund_deploy_address(&self, dest: &str, amount: u128) -> Result<()> {
        self.send_currency_with_flag(dest, amount, 16).await?;
        self.send_currency_with_flag(dest, amount, 2).await?;
        Ok(())
    }

    /// Single `sendCurrencyWithFlag(dest, value, {2: amount}, flag)` external call.
    pub async fn send_currency_with_flag(&self, dest: &str, amount: u128, flag: u8) -> Result<()> {
        self.call(
            "sendCurrencyWithFlag",
            json!({
                "dest": dest,
                "value": amount.to_string(),
                "ecc": { "2": amount.to_string() },
                "flag": flag,
            }),
        )
        .await
    }

    /// Plain ECC[2] SHELL transfer to an already-initialized account (flag 1),
    /// used to fund a wallet's spend budget.
    pub async fn send_shell(&self, dest: &str, amount: u128) -> Result<()> {
        self.send_currency_with_flag(dest, amount, 1).await
    }

    async fn call(&self, method: &str, input: Value) -> Result<()> {
        let encoded = encode_message(
            self.ctx.clone(),
            ParamsOfEncodeMessage {
                abi: Abi::Json(GIVER_ABI_JSON.to_string()),
                address: Some(self.address.clone()),
                deploy_set: None,
                call_set: Some(CallSet {
                    function_name: method.to_string(),
                    header: None,
                    input: Some(input),
                }),
                signer: Signer::Keys {
                    keys: self.keys.clone(),
                },
                processing_try_index: None,
                // v3 CapSignatureWithId — see airegistry::calls::network_signature_id.
                signature_id: None,
            },
        )
        .await
        .map_err(|e| anyhow!("encode giver {method}: {e}"))?;

        // `send_message` resolves the required routing fields itself: it parses
        // the destination (the Giver) from the BOC and reads the Giver's real
        // dapp_id from the chain — which is the all-zero system DApp, not the
        // Giver's own account_id. (An earlier hand-rolled dst_dapp_id failed
        // because the BK also requires the `account_id` field and rejects a
        // mismatch with the message destination.) It also surfaces a BM refusal
        // (e.g. QUEUE_OVERFLOW on a halted chain) as an `Err`, so a swallowed
        // funding failure can't masquerade as success here.
        super::query::send_message(&self.http, &self.endpoint, &encoded.message).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::contracts::GIVER_ABI;

    #[test]
    fn giver_abi_loads() {
        assert!(GIVER_ABI.function("sendCurrencyWithFlag").is_ok());
    }
}
