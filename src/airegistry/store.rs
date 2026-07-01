// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! airegistry object-store data model (§10).
//!
//! The wrapper caches **addresses/metadata only** (never secrets) under the
//! existing `ObjectStoreClient`. Keys are fully scoped by `network` + SuperRoot
//! (+ RootModel for lots/manifests) so they cannot collide across networks,
//! SuperRoot instances, or RootModels. `<sr>` / `<rm>` are short hashes of the
//! SuperRoot / RootModel addresses.

use anyhow::Result;
use serde_json::json;

use crate::state::AppState;

pub const KIND_SUPER_ROOT: &str = "airegistry.super_root";
pub const KIND_ROOT_MODEL: &str = "airegistry.root_model";
pub const KIND_MANIFEST: &str = "airegistry.manifest";
pub const KIND_TOKEN_LOT: &str = "airegistry.token_lot";
pub const KIND_OPER_WALLET: &str = "airegistry.oper_wallet";
pub const KIND_ENTITLEMENT: &str = "airegistry.entitlement";

/// A short (12-hex) content hash of an address — the `<sr>` / `<rm>` key segment.
pub fn short_hash(addr: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = hex::encode(Sha256::digest(addr.trim().as_bytes()));
    h[..12].to_string()
}

fn strip(pubkey: &str) -> &str {
    pubkey.trim().trim_start_matches("0x")
}

/// Object-store writer scoped to one network. Persists pointers as the creator /
/// consumer tools deploy/resolve contracts.
pub struct Store<'a> {
    state: &'a AppState,
    network: String,
}

impl<'a> Store<'a> {
    pub fn new(state: &'a AppState) -> Self {
        let network = state.network.name.clone();
        Self { state, network }
    }

    pub fn super_root_key(&self, super_root_pubkey: &str) -> String {
        format!("{}:{}", self.network, strip(super_root_pubkey))
    }
    pub fn root_model_key(&self, super_root_addr: &str, owner_pubkey: &str) -> String {
        format!(
            "{}:{}:{}",
            self.network,
            short_hash(super_root_addr),
            strip(owner_pubkey)
        )
    }
    pub fn manifest_key(
        &self,
        super_root_addr: &str,
        root_model_addr: &str,
        owner_pubkey: &str,
    ) -> String {
        format!(
            "{}:{}:{}:{}",
            self.network,
            short_hash(super_root_addr),
            short_hash(root_model_addr),
            strip(owner_pubkey)
        )
    }
    pub fn token_lot_key(
        &self,
        super_root_addr: &str,
        root_model_addr: &str,
        seller_pubkey: &str,
        nonce: u64,
    ) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.network,
            short_hash(super_root_addr),
            short_hash(root_model_addr),
            strip(seller_pubkey),
            nonce
        )
    }
    pub fn oper_wallet_key(&self, oper_wallet_id: &str) -> String {
        format!("{}:{}", self.network, oper_wallet_id)
    }
    pub fn entitlement_key(&self, token_addr: &str, oper_wallet_addr: &str) -> String {
        format!(
            "{}:{}:{}",
            self.network,
            token_addr.trim(),
            oper_wallet_addr.trim()
        )
    }

    pub async fn put_super_root(&self, pubkey: &str, address: &str) -> Result<()> {
        self.state
            .object_store()?
            .upsert(
                KIND_SUPER_ROOT,
                &self.super_root_key(pubkey),
                json!({ "address": address, "pubkey": strip(pubkey) }),
            )
            .await
            .map(|_| ())
    }

    pub async fn put_root_model(
        &self,
        super_root_addr: &str,
        owner_pubkey: &str,
        address: &str,
    ) -> Result<()> {
        self.state
            .object_store()?
            .upsert(
                KIND_ROOT_MODEL,
                &self.root_model_key(super_root_addr, owner_pubkey),
                json!({ "address": address, "super_root": super_root_addr }),
            )
            .await
            .map(|_| ())
    }

    pub async fn put_manifest(
        &self,
        super_root_addr: &str,
        root_model_addr: &str,
        owner_pubkey: &str,
        address: &str,
    ) -> Result<()> {
        self.state
            .object_store()?
            .upsert(
                KIND_MANIFEST,
                &self.manifest_key(super_root_addr, root_model_addr, owner_pubkey),
                json!({ "address": address, "root_model": root_model_addr, "super_root": super_root_addr }),
            )
            .await
            .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_token_lot(
        &self,
        super_root_addr: &str,
        root_model_addr: &str,
        seller_pubkey: &str,
        nonce: u64,
        address: &str,
        model_name: &str,
        endpoint: &str,
        package_sha256: Option<&str>,
    ) -> Result<()> {
        let mut body = json!({
            "address": address,
            "model_name": model_name,
            "endpoint": endpoint,
            "root_model": root_model_addr,
            "super_root": super_root_addr,
            "nonce": nonce,
        });
        if let Some(h) = package_sha256 {
            body["package_sha256"] = json!(h);
        }
        self.state
            .object_store()?
            .upsert(
                KIND_TOKEN_LOT,
                &self.token_lot_key(super_root_addr, root_model_addr, seller_pubkey, nonce),
                body,
            )
            .await
            .map(|_| ())
    }

    /// Cache the operational wallet's address pointer. Budget figures are NOT
    /// stored here — the live budget is the wallet's on-chain ECC[2] balance and
    /// the lot's entitlement counters (read via `airegistry_get_entitlement`);
    /// caching them would go permanently stale (the wrapper sees neither the
    /// second treasury confirmation nor the on-chain buys).
    pub async fn put_oper_wallet(&self, oper_wallet_id: &str, address: &str) -> Result<()> {
        self.state
            .object_store()?
            .upsert(
                KIND_OPER_WALLET,
                &self.oper_wallet_key(oper_wallet_id),
                json!({ "address": address }),
            )
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_is_12_hex_and_stable() {
        let a = short_hash("0:abc");
        assert_eq!(a.len(), 12);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, short_hash("0:abc"));
        assert_ne!(a, short_hash("0:abd"));
    }

    #[test]
    fn strip_normalizes_pubkey() {
        assert_eq!(strip("0xABCD"), "ABCD");
        assert_eq!(strip("  ef "), "ef");
    }
}
