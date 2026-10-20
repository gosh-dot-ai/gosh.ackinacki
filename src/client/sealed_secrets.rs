// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! REST client for namespace secret delivery (X25519 sealed-box).
//!
//! Wraps two endpoints on gosh.memory:
//!   POST /api/v1/agent/public-key/register   — register agent's X25519 pubkey
//!   POST /api/v1/agent/secrets/resolve       — fetch sealed namespace secrets
//!
//! Auth: Authorization: Bearer <principal_token> (swarm-agent token, bound to
//! a namespace + swarm). Optional X-GOSH-MEMORY-TOKEN transport header.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use x25519_dalek::StaticSecret;

use crate::client::crypto::{decrypt_namespace_secret, public_key_b64};

const ALGORITHM: &str = "x25519";
const NAMESPACE_SCOPE: &str = "namespace";

/// A reference to a sealed namespace secret.
#[derive(Debug, Clone, Serialize)]
pub struct SecretRef {
    pub name: String,
    pub scope: String,
}

impl SecretRef {
    pub fn namespace(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: NAMESPACE_SCOPE.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct EncryptedSecret {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    scope: String,
    #[allow(dead_code)]
    #[serde(default)]
    algorithm: String,
    #[allow(dead_code)]
    #[serde(default)]
    key_id: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct ResolveResponse {
    secrets: Vec<EncryptedSecret>,
}

/// Client for the agent secret-delivery REST surface.
#[derive(Clone)]
pub struct SealedSecretsClient {
    http: reqwest::Client,
    base_url: String,
    principal_token: String,
    transport_token: Option<String>,
    namespace_key: String,
    private_key: Arc<StaticSecret>,
}

impl SealedSecretsClient {
    pub fn new(
        http: reqwest::Client,
        base_url: &str,
        principal_token: &str,
        transport_token: Option<&str>,
        namespace_key: &str,
        private_key: Arc<StaticSecret>,
    ) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            principal_token: principal_token.to_string(),
            transport_token: transport_token.map(str::to_string),
            namespace_key: namespace_key.to_string(),
            private_key,
        }
    }

    pub fn private_key(&self) -> &StaticSecret {
        &self.private_key
    }

    pub fn namespace_key(&self) -> &str {
        &self.namespace_key
    }

    /// Register this agent's X25519 public key with gosh.memory.
    /// Idempotent — overwrites any prior binding for the same principal.
    pub async fn register_public_key(&self) -> Result<()> {
        let pk_b64 = public_key_b64(&self.private_key);
        let url = format!("{}/api/v1/agent/public-key/register", self.base_url);
        let body = json!({
            "public_key": pk_b64,
            "algorithm": ALGORITHM,
        });

        let mut req = self
            .http
            .post(&url)
            .bearer_auth(&self.principal_token)
            .json(&body);
        if let Some(tt) = &self.transport_token {
            req = req.header("X-GOSH-MEMORY-TOKEN", tt);
        }
        let resp = req.send().await.context("POST public-key/register")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("public-key register failed (HTTP {status}): {body}");
        }
        tracing::debug!(target: "ackinacki::secrets", "registered X25519 public key with gosh.memory");
        Ok(())
    }

    /// Resolve one or more namespace secrets. Returns plaintext values keyed
    /// by their requested name (after sealed-box decryption).
    pub async fn resolve(&self, names: &[&str]) -> Result<Vec<(String, String)>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let refs: Vec<SecretRef> = names.iter().map(|n| SecretRef::namespace(*n)).collect();

        let url = format!("{}/api/v1/agent/secrets/resolve", self.base_url);
        let body = json!({
            "key": self.namespace_key,
            "refs": refs,
        });

        let mut req = self
            .http
            .post(&url)
            .bearer_auth(&self.principal_token)
            .json(&body);
        if let Some(tt) = &self.transport_token {
            req = req.header("X-GOSH-MEMORY-TOKEN", tt);
        }
        let resp = req.send().await.context("POST secrets/resolve")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("secrets resolve failed (HTTP {status}): {body}");
        }

        let parsed: ResolveResponse = resp.json().await.context("parsing resolve response")?;
        let mut out = Vec::with_capacity(parsed.secrets.len());
        for sec in parsed.secrets {
            let plaintext = decrypt_namespace_secret(&self.private_key, &sec.ciphertext)
                .with_context(|| format!("decrypting secret '{}'", sec.name))?;
            out.push((sec.name, plaintext));
        }
        Ok(out)
    }

    /// Convenience: resolve a single secret, returning its plaintext value or `None` if absent.
    pub async fn resolve_one(&self, name: &str) -> Result<Option<String>> {
        let mut all = self.resolve(&[name]).await?;
        Ok(all.pop().map(|(_, v)| v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_ref_namespace_scope() {
        let r = SecretRef::namespace("foo");
        assert_eq!(r.scope, "namespace");
        assert_eq!(r.name, "foo");
    }
}
