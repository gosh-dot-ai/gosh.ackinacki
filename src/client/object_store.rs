// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Persistent agent-writable KV store via gosh.memory MCP `memory_object_*` tools.
//!
//! Used by ackinacki to persist wallet custodian keys, wallet addresses, and
//! other long-lived metadata generated at runtime. Authorized by the swarm-agent
//! Bearer token; ACL is enforced by gosh.memory via the bound `owner_principal_id`.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::client::mcp_http::McpHttpClient;

/// Parse an MCP tool response payload, failing loudly on malformed JSON instead
/// of silently swallowing it as `Value::Null`. This is what guarantees that a
/// HTML error page or a corrupted body surfaces as a real error rather than a
/// "successful" upsert that wrote nothing.
fn parse_tool_payload(tool: &str, text: &str) -> Result<Value> {
    serde_json::from_str::<Value>(text).with_context(|| {
        format!(
            "{tool}: response payload is not valid JSON (got {} bytes)",
            text.len()
        )
    })
}

/// Wrapper around MCP `memory_object_upsert` / `memory_object_get` / `memory_object_list`.
#[derive(Clone)]
pub struct ObjectStoreClient {
    mcp: McpHttpClient,
    namespace_key: String,
    swarm_id: String,
    agent_id: String,
}

impl ObjectStoreClient {
    pub fn new(
        http: reqwest::Client,
        base_url: &str,
        principal_token: &str,
        transport_token: Option<&str>,
        namespace_key: &str,
        swarm_id: &str,
        agent_id: &str,
    ) -> Self {
        Self {
            mcp: McpHttpClient::new(http, base_url, principal_token, transport_token),
            namespace_key: namespace_key.to_string(),
            swarm_id: swarm_id.to_string(),
            agent_id: agent_id.to_string(),
        }
    }

    /// Construct with an existing `McpHttpClient` (so multiple clients can share a session).
    pub fn from_mcp(
        mcp: McpHttpClient,
        namespace_key: &str,
        swarm_id: &str,
        agent_id: &str,
    ) -> Self {
        Self {
            mcp,
            namespace_key: namespace_key.to_string(),
            swarm_id: swarm_id.to_string(),
            agent_id: agent_id.to_string(),
        }
    }

    pub fn namespace_key(&self) -> &str {
        &self.namespace_key
    }

    pub fn swarm_id(&self) -> &str {
        &self.swarm_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Upsert a JSON body under (object_kind, object_key).
    pub async fn upsert(&self, object_kind: &str, object_key: &str, body: Value) -> Result<Value> {
        let args = json!({
            "key": self.namespace_key,
            "swarm_id": self.swarm_id,
            "object_kind": object_kind,
            "object_key": object_key,
            "agent_id": self.agent_id,
            "body": body,
        });
        let text = self.mcp.call_tool("memory_object_upsert", args).await?;
        let parsed = parse_tool_payload("memory_object_upsert", &text)?;
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            bail!("memory_object_upsert failed: {err}");
        }
        // Confirm the write actually happened: gosh.memory returns
        // `{"ok": true, "object": {...}}`. A response without those fields
        // means the call did NOT write — refuse to silently succeed.
        let ok_flag = parsed.get("ok").and_then(|v| v.as_bool()) == Some(true);
        let has_object = parsed.get("object").is_some();
        if !ok_flag && !has_object {
            bail!("memory_object_upsert response missing expected ok/object fields: {parsed}");
        }
        Ok(parsed)
    }

    /// Fetch one object by (object_kind, object_key). Returns the `body` dict
    /// on success, `Ok(None)` on NOT_FOUND, `Err` on auth/transport errors.
    pub async fn get(&self, object_kind: &str, object_key: &str) -> Result<Option<Value>> {
        let args = json!({
            "key": self.namespace_key,
            "swarm_id": self.swarm_id,
            "object_kind": object_kind,
            "object_key": object_key,
            "agent_id": self.agent_id,
        });
        let text = self.mcp.call_tool("memory_object_get", args).await?;
        let parsed = parse_tool_payload("memory_object_get", &text)?;
        if parsed.get("code").and_then(|v| v.as_str()) == Some("NOT_FOUND") {
            return Ok(None);
        }
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            bail!("memory_object_get failed: {err}");
        }
        let object = parsed
            .get("object")
            .ok_or_else(|| anyhow!("memory_object_get: missing object in response: {parsed}"))?;
        let body = object
            .get("body")
            .cloned()
            .ok_or_else(|| anyhow!("memory_object_get: missing body in object: {object}"))?;
        Ok(Some(body))
    }

    /// List objects by kind (optionally filtered by key prefix).
    pub async fn list(
        &self,
        object_kind: &str,
        object_key_prefix: Option<&str>,
        limit: Option<i64>,
    ) -> Result<Vec<Value>> {
        let mut args = json!({
            "key": self.namespace_key,
            "swarm_id": self.swarm_id,
            "object_kind": object_kind,
            "agent_id": self.agent_id,
            "limit": limit.unwrap_or(100),
        });
        if let Some(p) = object_key_prefix {
            args["object_key_prefix"] = json!(p);
        }
        let text = self.mcp.call_tool("memory_object_list", args).await?;
        let parsed = parse_tool_payload("memory_object_list", &text)?;
        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
            bail!("memory_object_list failed: {err}");
        }
        // Refuse to silently turn a malformed payload into an empty list —
        // upstream callers will otherwise believe "no objects" when the
        // request actually failed mid-flight.
        let objects = parsed
            .get("objects")
            .ok_or_else(|| anyhow!("memory_object_list: missing 'objects' field: {parsed}"))?
            .as_array()
            .ok_or_else(|| anyhow!("memory_object_list: 'objects' must be an array: {parsed}"))?
            .clone();
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tool_payload_accepts_valid_json() {
        let v = parse_tool_payload("test", r#"{"ok": true}"#).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn parse_tool_payload_rejects_html_body() {
        // Regression guard: an upstream proxy returning HTML used to be
        // swallowed as `Value::Null` and treated as success.
        let html = "<html><body>503 Service Unavailable</body></html>";
        let err = parse_tool_payload("test", html).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not valid JSON"), "unexpected error: {msg}");
    }

    #[test]
    fn parse_tool_payload_rejects_empty_body() {
        let err = parse_tool_payload("test", "").unwrap_err();
        assert!(format!("{err:#}").contains("not valid JSON"));
    }
}
