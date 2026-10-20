// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! [`BoxKey`] — authenticated public-key sealing (NaCl `crypto_box`) over
//! `tvm_client::crypto` (TVM SDK v3).
//!
//! Self-contained: depends only on the Acki Nacki / TVM crypto stack, **not** on
//! gosh.memory. Distinct from the ed25519 signing [`super::KeyPair`] — this is an
//! X25519 *encryption* identity.
//!
//! `nacl_box` is **authenticated**: a seal binds the sender's box key, so the
//! recipient both decrypts AND verifies who sent it. Handover (§3.1): the seller
//! seals an endpoint to the buyer's box public key; the buyer opens it with its
//! own box key + the seller's box public key.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tvm_client::crypto::{
    nacl_box, nacl_box_keypair, nacl_box_keypair_from_secret_key, nacl_box_open, ParamsOfNaclBox,
    ParamsOfNaclBoxKeyPairFromSecret, ParamsOfNaclBoxOpen,
};
use tvm_client::ClientContext;
use zeroize::Zeroizing;

use crate::airegistry::deploy::local_context;

/// A sealed message from [`BoxKey::encrypt_to`]: ciphertext plus the nonce the
/// recipient needs to open it. The recipient also needs the SENDER's box public
/// key (authenticated box).
#[derive(Debug, Clone)]
pub struct SealedMessage {
    /// 24-byte NaCl nonce (hex).
    pub nonce: String,
    /// Ciphertext (base64).
    pub ciphertext_b64: String,
}

/// An X25519 box keypair (NaCl `crypto_box`) — a peer's *encryption* identity.
/// Holds a zeroizing secret and is intentionally not `Clone` (so key material is
/// never silently duplicated).
pub struct BoxKey {
    ctx: Arc<ClientContext>,
    public_hex: String,
    secret_hex: Zeroizing<String>,
}

impl BoxKey {
    /// Generate a fresh random box keypair.
    pub fn generate() -> Result<Self> {
        let ctx = local_context()?;
        let kp = nacl_box_keypair(ctx.clone()).map_err(|e| anyhow!("nacl_box_keypair: {e}"))?;
        Ok(Self {
            ctx,
            public_hex: kp.public.clone(),
            secret_hex: Zeroizing::new(kp.secret.clone()),
        })
    }

    /// Load from a 32-byte secret key (hex); the public half is derived.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self> {
        let ctx = local_context()?;
        let kp = nacl_box_keypair_from_secret_key(
            ctx.clone(),
            ParamsOfNaclBoxKeyPairFromSecret {
                secret: secret_hex.trim().to_string(),
            },
        )
        .map_err(|e| anyhow!("nacl_box_keypair_from_secret_key: {e}"))?;
        Ok(Self {
            ctx,
            public_hex: kp.public.clone(),
            secret_hex: Zeroizing::new(kp.secret.clone()),
        })
    }

    /// This key's public half (hex) — share it so peers can [`BoxKey::encrypt_to`] it.
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// This key's secret half (hex) — export only to persist the identity.
    pub fn secret_hex(&self) -> &str {
        &self.secret_hex
    }

    /// Seal `plaintext` to `recipient_public_hex`, **authenticated** by this key.
    /// The recipient opens it with their own [`BoxKey`] + this key's public half.
    pub fn encrypt_to(
        &self,
        recipient_public_hex: &str,
        plaintext: &[u8],
    ) -> Result<SealedMessage> {
        use base64::Engine;
        let nonce: [u8; 24] = rand::random();
        let nonce_hex = hex::encode(nonce);
        let res = nacl_box(
            self.ctx.clone(),
            ParamsOfNaclBox {
                decrypted: base64::engine::general_purpose::STANDARD.encode(plaintext),
                nonce: nonce_hex.clone(),
                their_public: recipient_public_hex.trim().to_string(),
                secret: self.secret_hex.to_string(),
            },
        )
        .map_err(|e| anyhow!("nacl_box seal: {e}"))?;
        Ok(SealedMessage {
            nonce: nonce_hex,
            ciphertext_b64: res.encrypted,
        })
    }

    /// Open a [`SealedMessage`] sealed TO this key by `sender_public_hex`.
    /// Returns the plaintext bytes; fails if the sender key or nonce is wrong
    /// (authentication failure).
    pub fn open(&self, sender_public_hex: &str, sealed: &SealedMessage) -> Result<Vec<u8>> {
        use base64::Engine;
        let res = nacl_box_open(
            self.ctx.clone(),
            ParamsOfNaclBoxOpen {
                encrypted: sealed.ciphertext_b64.clone(),
                nonce: sealed.nonce.clone(),
                their_public: sender_public_hex.trim().to_string(),
                secret: self.secret_hex.to_string(),
            },
        )
        .map_err(|e| anyhow!("nacl_box_open: {e}"))?;
        base64::engine::general_purpose::STANDARD
            .decode(res.decrypted.trim())
            .map_err(|e| anyhow!("decode opened plaintext: {e}"))
    }
}

// Never derive Debug — it would expose the secret. Show only the public key.
impl std::fmt::Debug for BoxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxKey")
            .field("public", &self.public_hex)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_roundtrip_authenticated() {
        let alice = BoxKey::generate().unwrap();
        let bob = BoxKey::generate().unwrap();
        let msg = b"https://seller.example/endpoint";
        let sealed = alice.encrypt_to(bob.public_hex(), msg).unwrap();
        // Bob opens with Alice's public key (authenticated).
        let opened = bob.open(alice.public_hex(), &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn box_open_wrong_sender_fails() {
        let alice = BoxKey::generate().unwrap();
        let bob = BoxKey::generate().unwrap();
        let mallory = BoxKey::generate().unwrap();
        let sealed = alice.encrypt_to(bob.public_hex(), b"secret").unwrap();
        // Wrong claimed sender → authentication fails.
        assert!(bob.open(mallory.public_hex(), &sealed).is_err());
    }

    #[test]
    fn box_persist_restore_public_stable() {
        let k = BoxKey::generate().unwrap();
        let restored = BoxKey::from_secret_hex(k.secret_hex()).unwrap();
        assert_eq!(k.public_hex(), restored.public_hex());
    }

    #[test]
    fn box_debug_redacts_secret() {
        let k = BoxKey::generate().unwrap();
        let d = format!("{k:?}");
        assert!(
            !d.contains(k.secret_hex()),
            "Debug must not leak the secret"
        );
        assert!(d.contains(k.public_hex()));
    }
}
