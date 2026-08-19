// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! ed25519 signing keys — the identity that signs blockchain messages
//! (external-inbound calls and deploys).
//!
//! This is the *only* key a chain consumer needs. Secret delivery (X25519
//! sealed-box via gosh.memory, [`crate::client::sealed_secrets`]) is a separate
//! concern at a different layer and is intentionally not exposed here: the
//! ed25519 key is a credential the caller already holds, whereas the X25519 key
//! is an *agent's* root identity for **receiving** sealed credentials. They are
//! deliberately distinct — see the module-level discussion in `crate::sdk`.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

use super::types::{Pubkey, Signature};

/// An ed25519 signing keypair. Holds the 32-byte secret as a zeroizing hex
/// string (wiped on drop); the public key is derived. Intentionally **not**
/// `Clone` — key material is never silently duplicated; pass it by reference to
/// `ChainClient::call` / `deploy`.
pub struct KeyPair {
    public_hex: String,
    secret_hex: Zeroizing<String>,
}

impl KeyPair {
    /// Generate a fresh random keypair (OS RNG).
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// Load from a 32-byte secret key (hex, `0x`-optional); the public is derived.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self> {
        Ok(Self::from_signing_key(signing_key_from_hex(secret_hex)?))
    }

    fn from_signing_key(sk: SigningKey) -> Self {
        Self {
            public_hex: hex::encode(sk.verifying_key().as_bytes()),
            secret_hex: Zeroizing::new(hex::encode(sk.to_bytes())),
        }
    }

    /// The public key as a typed [`Pubkey`].
    pub fn public(&self) -> Pubkey {
        // public_hex is derived from a valid key, so this never fails.
        Pubkey::parse(&self.public_hex).expect("derived public key is valid 32-byte hex")
    }

    /// Bare 64-hex public key (the form the encoders take).
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// Bare 64-hex secret key — export only to persist the identity (the
    /// returned `str` borrows the zeroizing buffer).
    pub fn secret_hex(&self) -> &str {
        self.secret_hex.as_str()
    }

    /// Sign `message` with ed25519, returning the 64-byte [`Signature`].
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let sk = signing_key_from_hex(self.secret_hex.as_str())?;
        Signature::parse(&hex::encode(sk.sign(message).to_bytes()))
    }
}

// Never derive Debug — it would print the secret. Show only the public key.
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public_hex)
            .finish_non_exhaustive()
    }
}

/// Verify an ed25519 `signature` over `message` against `public`.
pub fn verify(public: &Pubkey, message: &[u8], signature: &Signature) -> Result<bool> {
    let pk: [u8; 32] = hex::decode(public.hex())?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| anyhow!("invalid public key: {e}"))?;
    let sig: [u8; 64] = hex::decode(signature.hex())?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    Ok(vk
        .verify(message, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok())
}

fn signing_key_from_hex(secret_hex: &str) -> Result<SigningKey> {
    let s = secret_hex.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let decoded = Zeroizing::new(hex::decode(s).map_err(|e| anyhow!("secret key not hex: {e}"))?);
    let mut bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("secret key must be 32 bytes"))?;
    let sk = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_sign_verify_roundtrip() {
        let kp = KeyPair::generate();
        let msg = b"acki nacki";
        let sig = kp.sign(msg).unwrap();
        assert!(
            verify(&kp.public(), msg, &sig).unwrap(),
            "valid signature verifies"
        );
        assert!(
            !verify(&kp.public(), b"tampered", &sig).unwrap(),
            "wrong message fails"
        );
    }

    #[test]
    fn from_secret_hex_derives_same_public() {
        let kp = KeyPair::generate();
        let again = KeyPair::from_secret_hex(kp.secret_hex()).unwrap();
        assert_eq!(
            kp.public_hex(),
            again.public_hex(),
            "public derived from secret is stable"
        );
        assert_eq!(kp.public().to_string(), format!("0x{}", kp.public_hex()));
    }

    #[test]
    fn from_secret_hex_accepts_0x_and_rejects_bad() {
        let kp = KeyPair::generate();
        let with0x = format!("0x{}", kp.secret_hex());
        assert_eq!(
            KeyPair::from_secret_hex(&with0x).unwrap().public_hex(),
            kp.public_hex()
        );
        assert!(KeyPair::from_secret_hex("nothex").is_err());
        assert!(KeyPair::from_secret_hex("00").is_err());
    }

    #[test]
    fn debug_never_leaks_secret() {
        let kp = KeyPair::generate();
        let dbg = format!("{kp:?}");
        assert!(
            !dbg.contains(kp.secret_hex()),
            "Debug must not print the secret"
        );
        assert!(dbg.contains(kp.public_hex()), "Debug shows the public key");
    }
}
