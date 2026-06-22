// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Sealed-box decryption for namespace secrets delivered by gosh.memory.
//!
//! Envelope format (gosh.memory v2 / GMS2):
//!   GMS2 (4 bytes magic)
//!   + ephemeral X25519 public key (32 bytes)
//!   + AES-GCM nonce (12 bytes)
//!   + AES-256-GCM ciphertext (includes 16-byte auth tag)
//!
//! Key derivation:
//!   shared = X25519(agent_private, ephemeral_public)
//!   aes_key = HKDF-SHA256(ikm=shared, salt=None, info=SECRET_INFO, len=32)
//!   plaintext = AES-256-GCM-decrypt(key=aes_key, nonce=nonce, aad=SECRET_INFO, ct=ciphertext)

use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use anyhow::{bail, Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const ENVELOPE_MAGIC: &[u8; 4] = b"GMS2";
const SECRET_INFO: &[u8] = b"gosh.memory/namespace-secret-delivery/v1";

/// Decrypt a single sealed-box ciphertext (base64-encoded GMS2 envelope).
pub fn decrypt_namespace_secret(
    private_key: &StaticSecret,
    ciphertext_b64: &str,
) -> Result<String> {
    use base64::Engine;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .context("base64 decode of sealed secret")?;

    // Minimum: 4 (magic) + 32 (ephemeral pk) + 12 (nonce) + 16 (tag) = 64
    if envelope.len() < 64 {
        bail!("sealed envelope too short: {} bytes", envelope.len());
    }
    if &envelope[..4] != ENVELOPE_MAGIC {
        bail!("invalid envelope magic: expected GMS2");
    }

    let ephemeral_public_bytes: [u8; 32] = envelope[4..36].try_into().unwrap();
    let nonce_bytes: [u8; 12] = envelope[36..48].try_into().unwrap();
    let ciphertext = &envelope[48..];

    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    let shared_secret = private_key.diffie_hellman(&ephemeral_public);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(SECRET_INFO, &mut aes_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {e}"))?;
    aes_key.zeroize();

    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: SECRET_INFO,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed"))?;

    String::from_utf8(plaintext).context("decrypted secret is not valid UTF-8")
}

/// Base64-encode an X25519 public key for registration.
pub fn public_key_b64(secret: &StaticSecret) -> String {
    use base64::Engine;
    let pk = PublicKey::from(secret);
    base64::engine::general_purpose::STANDARD.encode(pk.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use aes_gcm::Aes256Gcm;
    use aes_gcm::KeyInit;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::EphemeralSecret;

    fn encrypt_for(recipient_pk: &PublicKey, plaintext: &str) -> String {
        use base64::Engine;
        let mut rng = OsRng;
        let ephemeral = EphemeralSecret::random_from_rng(rng);
        let ephemeral_pk = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(recipient_pk);

        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(SECRET_INFO, &mut aes_key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext.as_bytes(),
            aad: SECRET_INFO,
        };
        let ct = cipher.encrypt(nonce, payload).unwrap();

        let mut envelope = Vec::new();
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.extend_from_slice(ephemeral_pk.as_bytes());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ct);
        base64::engine::general_purpose::STANDARD.encode(envelope)
    }

    #[test]
    fn roundtrip_decrypt() {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        let pk = PublicKey::from(&secret);
        let plaintext = "hello sealed world";
        let envelope = encrypt_for(&pk, plaintext);
        let decrypted = decrypt_namespace_secret(&secret, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_short_envelope() {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        use base64::Engine;
        let envelope = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let err = decrypt_namespace_secret(&secret, &envelope).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn rejects_bad_magic() {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        use base64::Engine;
        let mut bytes = vec![b'X'; 100];
        bytes[..4].copy_from_slice(b"WRNG");
        let envelope = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let err = decrypt_namespace_secret(&secret, &envelope).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn rejects_wrong_key() {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        let other = StaticSecret::random_from_rng(rng);
        let pk = PublicKey::from(&secret);
        let envelope = encrypt_for(&pk, "secret");
        let err = decrypt_namespace_secret(&other, &envelope).unwrap_err();
        assert!(err.to_string().contains("decrypt failed"));
    }

    #[test]
    fn public_key_b64_is_32_bytes_encoded() {
        let rng = OsRng;
        let secret = StaticSecret::random_from_rng(rng);
        use base64::Engine;
        let b64 = public_key_b64(&secret);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
