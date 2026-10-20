// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Bootstrap and authentication state for gosh.memory.
//!
//! Bootstrap file (passed via --bootstrap-file) contains:
//!   { "join_token": "gosh_join_<base64url(JSON)>",
//!     "secret_key": "<base64 32-byte X25519 private>" }
//!
//! After successful bootstrap, the principal_token + memory URL are persisted
//! to memory-auth.json (mode 0o600) so the agent can reconnect across restarts
//! without re-bootstrapping.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

const JOIN_PREFIX: &str = "gosh_join_";

/// Decoded join token payload (from `gosh_join_<base64url(JSON)>`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JoinToken {
    pub url: String,
    #[serde(default, alias = "token")]
    pub transport_token: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default, alias = "principal_auth_token")]
    pub principal_token: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub ca: Option<String>,
}

impl JoinToken {
    pub fn decode(raw: &str) -> Result<Self> {
        let body = raw
            .strip_prefix(JOIN_PREFIX)
            .ok_or_else(|| anyhow!("join token must start with '{JOIN_PREFIX}'"))?;
        let bytes = base64_url_decode(body).context("decoding base64url join body")?;
        let parsed: JoinToken =
            serde_json::from_slice(&bytes).context("parsing join token JSON")?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<()> {
        if self.url.trim().is_empty() {
            bail!("join token: url is required");
        }
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            bail!("join token: url must start with http:// or https://");
        }
        // ackinacki authenticates as a swarm-agent against the new gosh.memory
        // surface (Bearer principal token + REST sealed-box). A transport-only
        // token cannot drive any post-migration call site, so refuse it here
        // BEFORE main.rs has persisted state or deleted the bootstrap file —
        // otherwise an operator who hands us a transport-only token would lose
        // the bootstrap and end up with a non-functional memory-auth.json.
        let has_principal = self
            .principal_token
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !has_principal {
            bail!(
                "join token: principal_token is required (transport_token alone is insufficient \
                 for the swarm-agent API surface)"
            );
        }
        Ok(())
    }
}

/// Persisted auth state for reconnecting to gosh.memory.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MemoryAuthState {
    pub memory_url: String,
    #[serde(default)]
    pub transport_token: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub principal_token: Option<String>,
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
    #[serde(default)]
    pub tls_ca: Option<String>,
}

impl MemoryAuthState {
    pub fn from_join(token: JoinToken) -> Self {
        Self {
            memory_url: token.url,
            transport_token: token.transport_token,
            principal_id: token.principal_id,
            principal_token: token.principal_token,
            tls_fingerprint: token.fingerprint,
            tls_ca: token.ca,
        }
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("reading memory-auth at {}", path.display()))?;
        let parsed: MemoryAuthState =
            serde_json::from_str(&content).context("parsing memory-auth.json")?;
        Ok(Some(parsed))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private_text_file(path, &serde_json::to_string_pretty(self)?)
    }
}

/// Bootstrap file written by the operator to deliver join_token + X25519 secret.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapData {
    pub join_token: String,
    /// Base64-encoded 32-byte X25519 private key.
    pub secret_key: String,
}

impl BootstrapData {
    pub fn read(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("reading bootstrap file {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| "parsing bootstrap file JSON".to_string())
    }

    /// Decode the X25519 32-byte secret_key into raw bytes.
    pub fn decode_secret_key(&self) -> Result<[u8; 32]> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.secret_key.trim())
            .context("decoding bootstrap secret_key (base64)")?;
        if bytes.len() != 32 {
            bail!(
                "bootstrap secret_key must be exactly 32 bytes, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Default config directory: $HOME/.gosh-ackinacki
pub fn default_config_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".gosh-ackinacki")
}

/// Default memory-auth.json path.
pub fn default_memory_auth_path() -> PathBuf {
    default_config_dir().join("memory-auth.json")
}

/// Atomically write a `0o600` text file: create a uniquely-named temp file with
/// `mode(0o600)` up front (no world-readable window), write + fsync, then rename
/// into place. On non-Unix falls back to a plain write. Reused for any private
/// on-disk secret (memory-auth.json, the MCP server token).
pub fn write_private_text_file(path: &Path, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("memory-auth.json");
        let tmp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("creating tmp file at {}", tmp_path.display()))?;
        handle.write_all(content.as_bytes())?;
        handle.sync_all()?;
        fs::rename(&tmp_path, path).with_context(|| format!("renaming to {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content).with_context(|| format!("writing {}", path.display()))
    }
}

/// Standard base64url decoder (RFC 4648, no padding).
fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let trimmed = input.trim();
    // base64::URL_SAFE_NO_PAD is the canonical decoder
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .context("base64url decode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_text_file_is_0600_and_correct() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ackinacki-priv-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        write_private_text_file(&path, "perimeter-secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private file must be 0o600, got {mode:o}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "perimeter-secret");
        // Idempotent: a second write atomically replaces it, still 0o600.
        write_private_text_file(&path, "rotated").unwrap();
        let mode2 = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode2, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "rotated");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn encode_join(payload: &serde_json::Value) -> String {
        use base64::Engine;
        let json = serde_json::to_vec(payload).unwrap();
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        format!("{JOIN_PREFIX}{body}")
    }

    #[test]
    fn decode_minimal_join() {
        let token = encode_join(&serde_json::json!({
            "url": "https://memory.example:8000",
            "principal_token": "P",
        }));
        let decoded = JoinToken::decode(&token).unwrap();
        assert_eq!(decoded.url, "https://memory.example:8000");
        assert_eq!(decoded.principal_token.as_deref(), Some("P"));
    }

    #[test]
    fn decode_with_principal() {
        let token = encode_join(&serde_json::json!({
            "url": "http://localhost:8000",
            "principal_id": "agent:ackinacki",
            "principal_token": "P",
        }));
        let decoded = JoinToken::decode(&token).unwrap();
        assert_eq!(decoded.principal_id.as_deref(), Some("agent:ackinacki"));
        assert_eq!(decoded.principal_token.as_deref(), Some("P"));
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = JoinToken::decode("not_a_join_token").unwrap_err();
        assert!(err.to_string().contains("gosh_join_"));
    }

    #[test]
    fn rejects_no_token() {
        let token = encode_join(&serde_json::json!({"url": "http://localhost"}));
        let err = JoinToken::decode(&token).unwrap_err();
        assert!(err.to_string().contains("principal_token"));
    }

    #[test]
    fn rejects_transport_token_only() {
        // Regression guard: a transport-only token used to pass validate() and
        // would let main.rs persist memory-auth.json + delete the bootstrap
        // file BEFORE failing on the missing principal_token. Now this must
        // fail at decode() so no destructive side-effects happen.
        let token = encode_join(&serde_json::json!({
            "url": "http://localhost:8000",
            "transport_token": "T",
        }));
        let err = JoinToken::decode(&token).unwrap_err();
        assert!(
            err.to_string().contains("principal_token"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_principal_token() {
        let token = encode_join(&serde_json::json!({
            "url": "http://localhost:8000",
            "principal_token": "",
            "transport_token": "T",
        }));
        let err = JoinToken::decode(&token).unwrap_err();
        assert!(err.to_string().contains("principal_token"));
    }

    #[test]
    fn auth_state_roundtrip() {
        let tmpdir = std::env::temp_dir().join(format!("ackinacki-test-{}", uuid::Uuid::new_v4()));
        let path = tmpdir.join("memory-auth.json");
        let state = MemoryAuthState {
            memory_url: "https://m.example:8000".into(),
            transport_token: Some("t".into()),
            principal_id: Some("agent:test".into()),
            principal_token: Some("p".into()),
            tls_fingerprint: None,
            tls_ca: None,
        };
        state.save(&path).unwrap();
        let loaded = MemoryAuthState::load(&path).unwrap().unwrap();
        assert_eq!(state, loaded);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn auth_state_load_missing_returns_none() {
        let path = std::env::temp_dir().join(format!("nonexistent-{}.json", uuid::Uuid::new_v4()));
        let result = MemoryAuthState::load(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn bootstrap_decode_secret_key() {
        use base64::Engine;
        let bytes = [0xABu8; 32];
        let bootstrap = BootstrapData {
            join_token: "gosh_join_xxx".into(),
            secret_key: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        assert_eq!(bootstrap.decode_secret_key().unwrap(), bytes);
    }

    #[test]
    fn bootstrap_rejects_wrong_length() {
        use base64::Engine;
        let bootstrap = BootstrapData {
            join_token: "gosh_join_xxx".into(),
            secret_key: base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
        };
        let err = bootstrap.decode_secret_key().unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn from_join_extracts_fields() {
        let token = JoinToken {
            url: "http://x".into(),
            transport_token: Some("t".into()),
            principal_id: Some("agent:a".into()),
            principal_token: Some("p".into()),
            fingerprint: Some("sha256:abc".into()),
            ca: Some("---PEM---".into()),
        };
        let state = MemoryAuthState::from_join(token);
        assert_eq!(state.memory_url, "http://x");
        assert_eq!(state.principal_id.as_deref(), Some("agent:a"));
        assert_eq!(state.principal_token.as_deref(), Some("p"));
    }
}
