// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! [`Wallet`] — a multisig wallet handle (`SwarmMultisigWallet`): submit and
//! confirm transactions.
//!
//! A thin layer over [`ChainClient`]: a submit/confirm is just a signed external
//! call to the wallet with the multisig ABI. Whether a submit executes
//! immediately (a 1-of-1 wallet) or queues for confirmation (N-of-M) is decided
//! on-chain by the wallet's `reqConfirms`, not here.

use anyhow::Result;
use serde_json::{json, Value};

use crate::wallet::contracts::MULTISIG_ABI_JSON;

use super::client::ChainClient;
use super::keys::KeyPair;
use super::types::Address;

/// A multisig wallet handle. Construct with [`Wallet::new`].
#[derive(Clone)]
pub struct Wallet {
    client: ChainClient,
    address: Address,
}

impl Wallet {
    /// Bind to a deployed multisig at `address`, using `client` for transport.
    pub fn new(client: ChainClient, address: Address) -> Self {
        Self { client, address }
    }

    /// The wallet's address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Submit a plain transfer of `value` native VMSHELL to `dest`, signed by a
    /// custodian `keys`. On a 1-of-1 wallet it executes immediately; on an N-of-M
    /// it queues for [`Wallet::confirm`]. Returns the Block Manager send response.
    pub async fn submit(
        &self,
        dest: &Address,
        value: u128,
        bounce: bool,
        keys: &KeyPair,
    ) -> Result<Value> {
        self.submit_full(dest, value, &[], bounce, 1, "", keys)
            .await
    }

    /// Submit a transfer carrying extra currencies (`ecc`, e.g. `[(2, shell)]`
    /// for ECC[2] SHELL) and a `payload` cell — an encoded internal-call body
    /// (see [`crate::airegistry::calls::encode_internal_payload`]), or `""` for a
    /// plain transfer. `flag` is the multisig send flag (1 = ordinary).
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_full(
        &self,
        dest: &Address,
        value: u128,
        ecc: &[(u32, u128)],
        bounce: bool,
        flag: u8,
        payload_b64: &str,
        keys: &KeyPair,
    ) -> Result<Value> {
        let cc: serde_json::Map<String, Value> = ecc
            .iter()
            .map(|(id, v)| (id.to_string(), json!(v.to_string())))
            .collect();
        self.client
            .call(
                &self.address,
                MULTISIG_ABI_JSON,
                "submitTransaction",
                json!({
                    "dest": dest.with_workchain(),
                    "value": value.to_string(),
                    "cc": Value::Object(cc),
                    "bounce": bounce,
                    "flag": flag,
                    "payload": payload_b64,
                }),
                keys,
            )
            .await
    }

    /// Confirm a queued transaction by id — the second (and later) custodian on
    /// an N-of-M wallet. The id comes from the submit that queued it.
    pub async fn confirm(&self, transaction_id: u64, keys: &KeyPair) -> Result<Value> {
        self.client
            .call(
                &self.address,
                MULTISIG_ABI_JSON,
                "confirmTransaction",
                json!({ "transactionId": transaction_id.to_string() }),
                keys,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_binds_to_address() {
        let client = ChainClient::connect("https://shellnet.ackinacki.org").unwrap();
        let addr = Address::parse(&"2".repeat(64)).unwrap();
        let w = Wallet::new(client, addr.clone());
        assert_eq!(w.address(), &addr);
    }
}
