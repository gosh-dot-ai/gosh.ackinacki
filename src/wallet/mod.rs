// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Wallet operations for Acki Nacki UpdateCustodianMultisigWallet.

pub mod contracts;
pub mod deploy;
pub mod giver;
pub mod policy;
pub mod query;
pub mod transact;

use ed25519_dalek::SigningKey;

/// Build an ABI header (pubkey, time, expire) for an external message.
pub(crate) fn build_header(key: &SigningKey) -> serde_json::Value {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    serde_json::json!({
        "pubkey": hex::encode(key.verifying_key().as_bytes()),
        "time": now,
        "expire": (now / 1000) + 60,
    })
}

/// Encode bytes as standard base64.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
