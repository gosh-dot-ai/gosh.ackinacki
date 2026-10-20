// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! gosh.memory MCP client — fact ingestion and wallet policy lookup.
//!
//! Authenticates with a swarm-agent Bearer principal token + optional
//! transport perimeter token. Persistent agent-writable storage is handled
//! separately by `ObjectStoreClient`; sealed namespace secrets by
//! `SealedSecretsClient`.

#[cfg(feature = "block-stream")]
use anyhow::Context;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};

use crate::client::mcp_http::McpHttpClient;
#[cfg(feature = "block-stream")]
use crate::transform::BlockchainFact;

/// MCP client for facts + policy.
#[derive(Clone)]
pub struct MemoryClient {
    mcp: McpHttpClient,
    key: String,
    agent_id: String,
    swarm_id: String,
    principal_token: String,
}

impl MemoryClient {
    pub fn new(
        base_url: &str,
        key: &str,
        agent_id: &str,
        swarm_id: &str,
        principal_token: &str,
    ) -> Self {
        Self {
            mcp: McpHttpClient::new(reqwest::Client::new(), base_url, principal_token, None),
            key: key.to_string(),
            agent_id: agent_id.to_string(),
            swarm_id: swarm_id.to_string(),
            principal_token: principal_token.to_string(),
        }
    }

    pub fn with_transport_token(mut self, token: Option<&str>) -> Self {
        let tt = token.filter(|t| !t.is_empty()).map(str::to_string);
        // Rebuild the underlying MCP client with the new transport token.
        self.mcp = McpHttpClient::new(
            reqwest::Client::new(),
            self.mcp.base_url(),
            &self.principal_token,
            tt.as_deref(),
        );
        self
    }

    pub fn base_url(&self) -> &str {
        self.mcp.base_url()
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn swarm_id(&self) -> &str {
        &self.swarm_id
    }

    pub fn principal_token(&self) -> &str {
        &self.principal_token
    }

    /// Inject a batch of blockchain facts via `memory_ingest_asserted_facts`.
    #[cfg(feature = "block-stream")]
    pub async fn ingest_facts(&self, facts: &[BlockchainFact]) -> Result<Value> {
        let facts_json: Vec<Value> = facts
            .iter()
            .map(|f| {
                let source_id = f.metadata.get("source_id").cloned();
                let mut fact_json = json!({
                    "fact": f.fact,
                    "kind": f.kind,
                    "entities": f.entities,
                    "session": f.session,
                    "session_date": f.session_date,
                    "metadata": f.metadata,
                });
                if let Some(sid) = source_id {
                    fact_json["source_id"] = sid;
                }
                fact_json
            })
            .collect();

        let args = json!({
            "key": self.key,
            "facts": facts_json,
            "agent_id": self.agent_id,
            "swarm_id": self.swarm_id,
        });
        let text = self
            .mcp
            .call_tool("memory_ingest_asserted_facts", args)
            .await?;
        let parsed: Value = serde_json::from_str(&text)
            .with_context(|| format!("parsing memory_ingest_asserted_facts result: {text}"))?;
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            bail!("memory_ingest_asserted_facts failed: {err}");
        }
        Ok(parsed)
    }

    /// Store a wallet policy as a fact with metadata.
    ///
    /// The wallet address is keyed by its CANONICAL account id (both in the
    /// metadata filter key and the source_id) so a policy can never later be
    /// missed by looking it up under an equivalent alternate spelling (e.g.
    /// uppercase hex). `get_wallet_policy` canonicalizes its query key the same
    /// way, so the two always agree.
    pub async fn set_wallet_policy(&self, wallet_address: &str, policy: &Value) -> Result<Value> {
        let canon = crate::wallet::policy::canon_dest(wallet_address);
        // Force the canonical key into the stored metadata regardless of what the
        // caller put in `policy.wallet_address`.
        let mut metadata = policy.clone();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("wallet_address".into(), json!(canon));
        }
        let fact = json!({
            "fact": format!("Wallet policy for {canon}"),
            "kind": "constraint",
            "entities": [canon],
            "source_id": format!("wallet_policy:{canon}"),
            "metadata": metadata,
        });
        let args = json!({
            "key": self.key,
            "facts": [fact],
            "agent_id": self.agent_id,
            "swarm_id": self.swarm_id,
        });
        let text = self
            .mcp
            .call_tool("memory_ingest_asserted_facts", args)
            .await?;
        // Don't treat a corrupt/non-JSON store response as success — a silently
        // un-stored policy would later read back as "no policy" and fail open.
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| anyhow!("memory_ingest_asserted_facts returned invalid JSON: {e}"))?;
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            bail!("memory_ingest_asserted_facts failed: {err}");
        }
        Ok(parsed)
    }

    /// Query wallet policy by address. Returns the raw `memory_query` response
    /// envelope (for backwards-compat with `wallet::policy::parse_policy_from_memory`).
    pub async fn get_wallet_policy(&self, wallet_address: &str) -> Result<Value> {
        // Query by the SAME canonical key set_wallet_policy stored under.
        let canon = crate::wallet::policy::canon_dest(wallet_address);
        let args = json!({
            "key": self.key,
            "filter": {
                "kind": "constraint",
                "metadata.wallet_address": canon,
                "metadata.enabled": true,
            },
            "agent_id": self.agent_id,
            "swarm_id": self.swarm_id,
        });
        let text = self.mcp.call_tool("memory_query", args).await?;
        // Fail-closed: a malformed memory_query payload (a proxy/HTML error body,
        // a truncated response, etc.) must NOT silently become an empty policy
        // that lets the spend through. Reject invalid JSON so the shared
        // fail-closed policy gate actually rejects on lookup corruption.
        let parsed: Value = serde_json::from_str(&text)
            .map_err(|e| anyhow!("memory_query returned invalid JSON (fail closed): {e}"))?;
        // Wrap as the legacy /result/content/0/text envelope so policy parsers
        // can stay unchanged.
        Ok(json!({
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": parsed.get("error").is_some(),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trims_trailing_slash() {
        let c = MemoryClient::new("http://example.com/", "key", "agent", "swarm", "tok");
        assert_eq!(c.base_url(), "http://example.com");
    }

    #[test]
    fn accessors() {
        let c = MemoryClient::new("http://host:8000", "my-key", "my-agent", "my-swarm", "P");
        assert_eq!(c.base_url(), "http://host:8000");
        assert_eq!(c.key(), "my-key");
        assert_eq!(c.agent_id(), "my-agent");
        assert_eq!(c.swarm_id(), "my-swarm");
        assert_eq!(c.principal_token(), "P");
    }

    #[test]
    fn with_transport_token_sets_value() {
        let c = MemoryClient::new("http://x", "k", "a", "s", "P").with_transport_token(Some("T"));
        // We don't expose the transport token; just check it doesn't panic and
        // the rest of the state is preserved.
        assert_eq!(c.base_url(), "http://x");
    }

    #[test]
    fn with_empty_transport_token_is_none() {
        let c = MemoryClient::new("http://x", "k", "a", "s", "P").with_transport_token(Some(""));
        assert_eq!(c.base_url(), "http://x");
    }
}
