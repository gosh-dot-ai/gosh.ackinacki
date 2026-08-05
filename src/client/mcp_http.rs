// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Shared low-level helper for calling MCP tools over HTTP.
//!
//! Handles:
//!  - Lazy `initialize` handshake (captures `Mcp-Session-Id`)
//!  - `notifications/initialized` after initialize
//!  - `tools/call` with session header
//!  - Response parsing for both `application/json` and `text/event-stream` bodies
//!  - Bearer principal token + optional `x-server-token` perimeter token

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// Shared MCP HTTP client. Cheap to clone (everything wrapped in Arc).
#[derive(Clone)]
pub struct McpHttpClient {
    http: reqwest::Client,
    base_url: String,
    principal_token: String,
    transport_token: Option<String>,
    /// Session id captured from the `Mcp-Session-Id` response header on `initialize`.
    /// Concurrent initializers may race; the last write wins. Idempotent on the server side.
    session_id: Arc<parking_lot::Mutex<Option<String>>>,
}

impl McpHttpClient {
    pub fn new(
        http: reqwest::Client,
        base_url: &str,
        principal_token: &str,
        transport_token: Option<&str>,
    ) -> Self {
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            principal_token: principal_token.to_string(),
            transport_token: transport_token.map(str::to_string),
            session_id: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Run `initialize` + `notifications/initialized`. Fast-path returns if a
    /// session id is already cached. Concurrent first-callers may race; the
    /// server accepts duplicate `initialize` and we keep the latest session.
    async fn ensure_initialized(&self) -> Result<()> {
        if self.session_id.lock().is_some() {
            return Ok(());
        }

        let init_body = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "gosh-ackinacki", "version": env!("CARGO_PKG_VERSION")},
            }
        });

        let resp = self
            .raw_post(&init_body, None)
            .await
            .context("MCP initialize")?;
        let sid = resp
            .headers()
            .get("mcp-session-id")
            .or_else(|| resp.headers().get("Mcp-Session-Id"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("MCP initialize HTTP {status}: {body}");
        }
        if let Some(sid) = sid {
            *self.session_id.lock() = Some(sid);
        }

        // Optional: notifications/initialized (server may require this).
        // Resolve sid into an owned Option<String> BEFORE awaiting so the
        // parking_lot guard is dropped (parking_lot guards are !Send and would
        // otherwise be held across the await, making the future !Send).
        let sid_owned = self.session_id.lock().clone();
        let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let _ = self.raw_post(&notif, sid_owned.as_deref()).await;
        Ok(())
    }

    /// Call an MCP tool by name with the given arguments. Returns the parsed
    /// JSON text payload (after extracting `result.content[0].text`).
    pub async fn call_tool(&self, tool: &str, arguments: Value) -> Result<String> {
        self.ensure_initialized().await?;

        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
            }
        });
        let sid = self.session_id.lock().clone();
        let resp = self.raw_post(&body, sid.as_deref()).await?;
        let status = resp.status();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let raw_body = resp
            .text()
            .await
            .with_context(|| format!("reading {tool} response body"))?;

        if !status.is_success() {
            bail!("{tool} HTTP {status}: {raw_body}");
        }

        let envelope = parse_jsonrpc_envelope(&content_type, &raw_body)
            .with_context(|| format!("parsing {tool} envelope"))?;

        if let Some(err) = envelope.get("error") {
            if !err.is_null() {
                bail!("MCP error from {tool}: {err}");
            }
        }
        if envelope
            .pointer("/result/isError")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            let msg = envelope
                .pointer("/result/content/0/text")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown tool error");
            bail!("{tool} tool error: {msg}");
        }
        let text = envelope
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing text in {tool} response"))?
            .to_string();
        Ok(text)
    }

    /// Low-level POST to `/mcp` with auth + optional session header. Caller
    /// inspects the response.
    async fn raw_post(&self, body: &Value, session_id: Option<&str>) -> Result<reqwest::Response> {
        let url = format!("{}/mcp", self.base_url);
        let mut req = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .bearer_auth(&self.principal_token)
            .json(body);
        if let Some(tt) = &self.transport_token {
            req = req.header("x-server-token", tt);
        }
        if let Some(sid) = session_id {
            req = req.header("Mcp-Session-Id", sid);
        }
        req.send().await.with_context(|| format!("POST {url}"))
    }
}

/// Parse a JSON-RPC envelope from either a raw `application/json` body or an
/// MCP `text/event-stream` (`event: message\ndata: <json>\n\n`) body.
fn parse_jsonrpc_envelope(content_type: &str, body: &str) -> Result<Value> {
    let body = body.trim();
    if content_type.starts_with("text/event-stream") {
        // Read all `data:` lines (last `data:` wins for the response envelope).
        let mut last_data: Option<&str> = None;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("data: ") {
                last_data = Some(rest);
            } else if let Some(rest) = line.strip_prefix("data:") {
                last_data = Some(rest.trim_start());
            }
        }
        let data = last_data.ok_or_else(|| anyhow!("no `data:` line in SSE response: {body:?}"))?;
        serde_json::from_str(data).with_context(|| format!("SSE data line: {data}"))
    } else {
        serde_json::from_str(body).with_context(|| format!("JSON body: {body}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_body() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"{}"}]}}"#;
        let env = parse_jsonrpc_envelope("application/json", raw).unwrap();
        assert_eq!(env["id"], 1);
    }

    #[test]
    fn parse_sse_body() {
        let raw = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"text\":\"ok\"}]}}\n\n";
        let env = parse_jsonrpc_envelope("text/event-stream", raw).unwrap();
        assert_eq!(env["result"]["content"][0]["text"], "ok");
    }

    #[test]
    fn parse_sse_with_multiple_data_takes_last() {
        let raw = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"first\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"last\"}\n\n";
        let env = parse_jsonrpc_envelope("text/event-stream", raw).unwrap();
        assert_eq!(env["result"], "last");
    }

    #[test]
    fn parse_sse_no_data_errors() {
        let raw = "event: ping\n\n";
        assert!(parse_jsonrpc_envelope("text/event-stream", raw).is_err());
    }
}
