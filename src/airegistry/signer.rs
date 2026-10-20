// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Signing-credential pointer resolution (§5).
//!
//! The wrapper never embeds secrets. Creator (seller) tools take a `signer_ref`
//! describing *where* the signing key lives; the host owns the namespace and
//! decides the kind:
//!
//! ```jsonc
//! { "kind": "object",           "name": "airegistry:seller:<pubkey>:privkey" }
//! { "kind": "namespace_secret", "name": "airegistry/seller/<id>/privkey" }
//! ```
//!
//! Resolution reuses the migration primitives: `object` →
//! [`ObjectStoreClient::get`], `namespace_secret` →
//! [`SealedSecretsClient::resolve_one`]. Wallet-internal calls (consumer
//! buy/confirm, treasury top-up) do NOT use `signer_ref` — they use the named
//! wallet custodian keys (`wallet:{id}:{role}`), exactly like `send_transaction`.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;

use crate::state::AppState;

/// Object kind under which creator `signer_ref { kind: object }` privkeys live.
pub const AIREGISTRY_SIGNER_KIND: &str = "ackinacki.airegistry.privkey";

/// A resolved signing keypair (both hex, no `0x`).
pub struct Signer {
    pub public: String,
    pub secret: String,
}

/// Where a creator signing key lives.
pub enum SignerRef {
    /// Object-store privkey the agent itself wrote (body `{ "value": <hex> }`).
    Object { name: String },
    /// Namespace secret seeded by an admin, delivered via sealed-box.
    NamespaceSecret { name: String },
}

impl SignerRef {
    /// Parse a `signer_ref` JSON object: `{ "kind": "object"|"namespace_secret",
    /// "name": "..." }`.
    pub fn parse(v: &Value) -> Result<Self> {
        let kind = v.get("kind").and_then(|k| k.as_str()).unwrap_or_default();
        let name = v
            .get("name")
            .and_then(|n| n.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("signer_ref.name is required"))?
            .to_string();
        match kind {
            "object" => Ok(SignerRef::Object { name }),
            "namespace_secret" => Ok(SignerRef::NamespaceSecret { name }),
            other => bail!("signer_ref.kind must be 'object' or 'namespace_secret', got '{other}'"),
        }
    }

    /// Resolve to a keypair: fetch the secret from its source, derive the public
    /// key from it.
    pub async fn resolve(&self, state: &AppState) -> Result<Signer> {
        let secret = match self {
            SignerRef::Object { name } => state
                .object_store()?
                .get(AIREGISTRY_SIGNER_KIND, name)
                .await?
                .and_then(|b| b.get("value").and_then(|v| v.as_str()).map(String::from))
                .ok_or_else(|| anyhow!("signer_ref object '{name}' not found"))?,
            SignerRef::NamespaceSecret { name } => state
                .sealed_secrets()?
                .resolve_one(name)
                .await?
                .ok_or_else(|| anyhow!("signer_ref namespace secret '{name}' not seeded"))?,
        };
        let public = derive_public(&secret)?;
        Ok(Signer { public, secret })
    }
}

/// Derive the ed25519 public key (hex) from a 32-byte secret (hex).
pub fn derive_public(secret_hex: &str) -> Result<String> {
    let bytes =
        hex::decode(secret_hex.trim()).map_err(|e| anyhow!("signer secret not hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("signer secret must be 32 bytes"))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    Ok(hex::encode(sk.verifying_key().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_object_and_namespace() {
        match SignerRef::parse(&json!({ "kind": "object", "name": "a:b" })).unwrap() {
            SignerRef::Object { name } => assert_eq!(name, "a:b"),
            _ => panic!("expected object"),
        }
        match SignerRef::parse(&json!({ "kind": "namespace_secret", "name": "x/y" })).unwrap() {
            SignerRef::NamespaceSecret { name } => assert_eq!(name, "x/y"),
            _ => panic!("expected namespace_secret"),
        }
    }

    #[test]
    fn parse_rejects_bad_kind_or_missing_name() {
        assert!(SignerRef::parse(&json!({ "kind": "object" })).is_err());
        assert!(SignerRef::parse(&json!({ "kind": "weird", "name": "n" })).is_err());
    }

    #[test]
    fn derive_public_is_stable_and_32_bytes() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sec = hex::encode(sk.to_bytes());
        let pubk = derive_public(&sec).unwrap();
        assert_eq!(pubk, hex::encode(sk.verifying_key().as_bytes()));
        assert_eq!(pubk.len(), 64);
        assert!(derive_public("nothex").is_err());
        assert!(derive_public("00").is_err());
    }
}
