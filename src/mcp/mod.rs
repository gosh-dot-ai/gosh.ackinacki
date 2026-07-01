// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! MCP server: JSON-RPC 2.0 over HTTP with x-server-token auth.

pub mod airegistry;
pub mod tools;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::cors::CorsLayer;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

/// Token auth middleware — mirrors gosh.memory's x-server-token pattern.
/// /health is public, everything else requires the token.
async fn auth_middleware(State(token): State<String>, req: Request<Body>, next: Next) -> Response {
    // /health is always public
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get("x-server-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Constant-time comparison to prevent timing side-channel
    let matches = provided.len() == token.len()
        && provided
            .bytes()
            .zip(token.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !matches {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Unauthorized"})),
        )
            .into_response();
    }

    next.run(req).await
}

async fn health() -> &'static str {
    "ok"
}

async fn handle_rpc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let id = req.id.clone();

    match req.method.as_str() {
        "initialize" => {
            let result = serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "gosh-ackinacki",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            });
            (StatusCode::OK, Json(JsonRpcResponse::ok(id, result)))
        }
        "tools/list" => {
            let result = serde_json::json!({
                "tools": tools::list_tools(state.mode())
            });
            (StatusCode::OK, Json(JsonRpcResponse::ok(id, result)))
        }
        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            match tools::call_tool(&state, tool_name, args).await {
                Ok(result) => {
                    let text =
                        serde_json::to_string(&result).unwrap_or("<serialization error>".into());
                    let wrapped = serde_json::json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false,
                    });
                    (StatusCode::OK, Json(JsonRpcResponse::ok(id, wrapped)))
                }
                Err(e) => {
                    let wrapped = serde_json::json!({
                        "content": [{"type": "text", "text": e.to_string()}],
                        "isError": true,
                    });
                    (StatusCode::OK, Json(JsonRpcResponse::ok(id, wrapped)))
                }
            }
        }
        _ => (
            StatusCode::OK,
            Json(JsonRpcResponse::err(
                id,
                -32601,
                format!("method not found: {}", req.method),
            )),
        ),
    }
}

pub fn router(state: Arc<AppState>, server_token: &str) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/mcp", post(handle_rpc))
        .layer(middleware::from_fn_with_state(
            server_token.to_string(),
            auth_middleware,
        ))
        // Deny all cross-origin requests (CorsLayer::new() defaults to deny-all).
        .layer(CorsLayer::new())
        .with_state(state)
}

pub async fn serve(
    bind: SocketAddr,
    state: Arc<AppState>,
    server_token: &str,
) -> anyhow::Result<()> {
    if !bind.ip().is_loopback() {
        tracing::warn!(
            "MCP server binding to non-localhost address {bind} without TLS. \
             In production, terminate TLS at a reverse proxy in front of this service."
        );
    }
    let app = router(state, server_token);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("MCP server listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
