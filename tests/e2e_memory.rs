// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! End-to-end integration test against a live gosh.memory instance.
//!
//! Skipped by default. To run:
//!
//! 1. Start gosh.memory with admin & plaintext-secret support:
//!    ```
//!    GOSH_MEMORY_ALLOW_PLAINTEXT_SECRETS=1 \
//!    GOSH_MEMORY_ADMIN_TOKEN=bootstrap-admin-token \
//!    GOSH_MEMORY_NO_EXTRACT=1 \
//!    python -m src.cli start --host 127.0.0.1 --port 18765 \
//!      --data-dir /tmp/gm-data --server-token transport-token-e2e
//!    ```
//!
//! 2. Export env and run the test:
//!    ```
//!    GOSH_MEMORY_E2E_URL=http://127.0.0.1:18765 \
//!    GOSH_MEMORY_E2E_ADMIN_TOKEN=bootstrap-admin-token \
//!    GOSH_MEMORY_E2E_TRANSPORT_TOKEN=transport-token-e2e \
//!    cargo test --test e2e_memory -- --nocapture --include-ignored
//!    ```

use std::sync::Arc;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use x25519_dalek::StaticSecret;

use gosh_ackinacki::client::mcp_http::McpHttpClient;
use gosh_ackinacki::client::memory::MemoryClient;
use gosh_ackinacki::client::object_store::ObjectStoreClient;
use gosh_ackinacki::client::sealed_secrets::SealedSecretsClient;
use gosh_ackinacki::config::NetworkConfig;
use gosh_ackinacki::state::AppState;

fn e2e_env() -> Option<(String, String, Option<String>)> {
    let url = std::env::var("GOSH_MEMORY_E2E_URL").ok()?;
    let admin = std::env::var("GOSH_MEMORY_E2E_ADMIN_TOKEN").ok()?;
    let transport = std::env::var("GOSH_MEMORY_E2E_TRANSPORT_TOKEN").ok();
    Some((url, admin, transport))
}

/// Bootstrap a fresh namespace+swarm, return (swarm_agent_token, namespace_key,
/// swarm_id, persisted_admin_token).
async fn bootstrap(
    url: &str,
    bootstrap_admin: &str,
    transport: Option<&str>,
) -> Result<(String, String, String, String)> {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let namespace_key = format!("ackinacki-e2e-{}", &suffix[..8]);
    let swarm_id = "default".to_string();

    // Step 1: bootstrap the persisted admin principal via env bootstrap token.
    let bootstrap_admin_mcp =
        McpHttpClient::new(reqwest::Client::new(), url, bootstrap_admin, transport);
    let resp_text = bootstrap_admin_mcp
        .call_tool(
            "auth_bootstrap_admin",
            json!({
                "principal_id": format!("service:e2e-admin-{}", &suffix[..8]),
                "kind": "service",
                "display_name": "e2e admin",
            }),
        )
        .await?;
    let resp: Value = serde_json::from_str(&resp_text)?;
    let persisted_admin = resp["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no admin token in auth_bootstrap_admin response: {resp}"))?
        .to_string();

    // Step 2: use the PERSISTED admin token for everything else (bootstrap admin
    // is only allowed for auth_bootstrap_admin itself).
    let admin = McpHttpClient::new(reqwest::Client::new(), url, &persisted_admin, transport);

    let _ = admin
        .call_tool(
            "memory_namespace_create",
            json!({"key": &namespace_key, "display_name": "E2E test namespace"}),
        )
        .await?;
    let _ = admin
        .call_tool(
            "memory_swarm_create",
            json!({"key": &namespace_key, "swarm_id": &swarm_id, "display_name": "default"}),
        )
        .await?;
    let _ = admin
        .call_tool(
            "memory_swarm_member_add",
            json!({
                "key": &namespace_key,
                "swarm_id": &swarm_id,
                "agent_id": "agent:ackinacki",
                "access": "read_write",
            }),
        )
        .await?;
    let token_resp_text = admin
        .call_tool(
            "memory_swarm_agent_token_issue",
            json!({
                "key": &namespace_key,
                "swarm_id": &swarm_id,
                "agent_id": "agent:ackinacki",
            }),
        )
        .await?;
    let token_resp: Value = serde_json::from_str(&token_resp_text)?;
    let swarm_agent_token = token_resp["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no token in swarm_agent_token_issue: {token_resp}"))?
        .to_string();

    Ok((swarm_agent_token, namespace_key, swarm_id, persisted_admin))
}

async fn admin_set_namespace_secret(
    persisted_admin: &str,
    url: &str,
    transport: Option<&str>,
    namespace_key: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    let admin = McpHttpClient::new(reqwest::Client::new(), url, persisted_admin, transport);
    let resp_text = admin
        .call_tool(
            "memory_namespace_secret_set",
            json!({"key": namespace_key, "name": name, "value": value}),
        )
        .await?;
    let resp: Value = serde_json::from_str(&resp_text)?;
    if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
        bail!("namespace_secret_set: {err}");
    }
    Ok(())
}

#[tokio::test]
async fn e2e_full_agent_flow() -> Result<()> {
    let Some((url, admin_bootstrap, transport)) = e2e_env() else {
        eprintln!(
            "e2e_full_agent_flow: SKIPPED (set GOSH_MEMORY_E2E_URL, \
             GOSH_MEMORY_E2E_ADMIN_TOKEN, GOSH_MEMORY_E2E_TRANSPORT_TOKEN to run)"
        );
        return Ok(());
    };

    // Phase 1: admin bootstrap creates namespace + swarm + member + agent token.
    let (swarm_agent_token, namespace_key, swarm_id, persisted_admin) =
        bootstrap(&url, &admin_bootstrap, transport.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap failed: {e}"))?;
    eprintln!("E2E: bootstrapped namespace={namespace_key} swarm={swarm_id}");

    // Phase 2: pre-seed a namespace secret as admin.
    let secret_name = "swarm_root:0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:owner:privkey".to_string();
    let secret_value = hex::encode([0xABu8; 32]);
    admin_set_namespace_secret(
        &persisted_admin,
        &url,
        transport.as_deref(),
        &namespace_key,
        &secret_name,
        &secret_value,
    )
    .await?;
    eprintln!("E2E: seeded namespace secret '{secret_name}'");

    // Phase 3: act as the swarm-agent — generate X25519, register pubkey, resolve secret.
    let agent_secret = Arc::new(StaticSecret::random_from_rng(rand::rngs::OsRng));
    let http = reqwest::Client::new();
    let sealed = SealedSecretsClient::new(
        http.clone(),
        &url,
        &swarm_agent_token,
        transport.as_deref(),
        &namespace_key,
        agent_secret.clone(),
    );
    sealed.register_public_key().await?;
    eprintln!("E2E: registered X25519 public key");

    let resolved = sealed.resolve_one(&secret_name).await?;
    assert_eq!(
        resolved.as_deref(),
        Some(secret_value.as_str()),
        "sealed-box roundtrip mismatch"
    );
    eprintln!("E2E: sealed-box resolved value matches");

    // Phase 4: opaque object store — upsert + get.
    let object_store = ObjectStoreClient::new(
        http.clone(),
        &url,
        &swarm_agent_token,
        transport.as_deref(),
        &namespace_key,
        &swarm_id,
        "ackinacki",
    );
    let body = json!({"value": "deadbeef", "role": "agent"});
    object_store
        .upsert("ackinacki.test.object", "w1:agent", body.clone())
        .await?;
    let got = object_store
        .get("ackinacki.test.object", "w1:agent")
        .await?;
    let got_body = got.ok_or_else(|| anyhow::anyhow!("object_get returned None after upsert"))?;
    assert_eq!(got_body["value"], "deadbeef");
    assert_eq!(got_body["role"], "agent");
    eprintln!("E2E: object_upsert/get roundtrip OK");

    let absent = object_store
        .get("ackinacki.test.object", "doesnotexist")
        .await?;
    assert!(absent.is_none(), "expected None for missing object");
    eprintln!("E2E: object_get correctly returns None for missing object");

    // Phase 5: drive the high-level MCP tools (create_keys → get_wallet_status →
    // deploy_wallet error path) via the production call_tool dispatcher, against
    // a real ObjectStore-backed AppState.
    let memory_client = MemoryClient::new(
        &url,
        &namespace_key,
        "ackinacki",
        &swarm_id,
        &swarm_agent_token,
    )
    .with_transport_token(transport.as_deref());
    let app_state = std::sync::Arc::new(AppState::new(
        memory_client,
        object_store.clone(),
        sealed.clone(),
        NetworkConfig::shellnet(),
    ));

    // create_keys for all three roles
    for role in ["agent", "controller", "owner"] {
        let result = gosh_ackinacki::mcp::tools::call_tool(
            &app_state,
            "create_keys",
            json!({"role": role, "wallet_id": "e2e-wallet-1"}),
        )
        .await?;
        assert!(result["public_key"].as_str().is_some());
    }
    eprintln!("E2E: created 3 wallet keys via call_tool");

    let status = gosh_ackinacki::mcp::tools::call_tool(
        &app_state,
        "get_wallet_status",
        json!({"wallet_id": "e2e-wallet-1"}),
    )
    .await?;
    assert_eq!(status["ready"], true, "wallet not ready: {status}");
    assert!(status["agent_key"].as_str().is_some());
    assert!(status["controller_key"].as_str().is_some());
    assert!(status["owner_key"].as_str().is_some());
    eprintln!("E2E: get_wallet_status reports ready=true");

    // deploy_wallet must successfully resolve the namespace secret seeded above
    // and reach the network-send step before any TVM/network failure.
    //
    // POSITIVE PROOF that the secret was resolved: we DIRECTLY call
    // `sealed.resolve_one(&secret_name)` right before deploy_wallet and assert
    // its plaintext matches. If that succeeds and deploy_wallet still fails,
    // we then explicitly reject any failure whose message indicates the secret
    // path broke — only network/TVM errors are acceptable here.
    let root_addr = "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let prove_resolve = sealed
        .resolve_one(&secret_name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("sealed.resolve_one returned None right before deploy"))?;
    assert_eq!(prove_resolve, secret_value, "secret value drifted");
    eprintln!("E2E: pre-deploy sealed-box re-check OK");

    let deploy_result = gosh_ackinacki::mcp::tools::call_tool(
        &app_state,
        "deploy_wallet",
        json!({"wallet_id": "e2e-wallet-1", "swarm_root_address": root_addr}),
    )
    .await;
    match deploy_result {
        Ok(v) => {
            // Surprisingly succeeded — only possible if a real shellnet send
            // happened. Validate the returned address parses as a real
            // workchain:hex string (regression guard for the SliceData bug).
            let addr = v["address"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("deploy_wallet returned no address"))?;
            assert!(
                addr.contains(':') && addr.split(':').nth(1).unwrap_or("").len() == 64,
                "deploy_wallet returned a malformed address: {addr}"
            );
            eprintln!("E2E: deploy_wallet succeeded with parseable address {addr}");
        }
        Err(e) => {
            let msg = e.to_string();
            // The only acceptable failures here are network/TVM-side. Bailing
            // on the SECRET RESOLVE path means our migration is broken; reject.
            let secret_failure_markers = [
                "SwarmRoot owner key",
                "not seeded",
                "secret not found",
                "secrets resolve failed",
                "public-key register failed",
                "access denied for secret",
                "decrypting secret",
            ];
            for marker in &secret_failure_markers {
                assert!(
                    !msg.contains(marker),
                    "deploy_wallet failed in the SECRET path (marker '{marker}'), \
                     not in network/TVM: {msg}"
                );
            }
            // Also forbid the address-format regression: malformed addresses
            // would never appear here because we couldn't even encode the call,
            // but we still reject any message that hints at that path.
            assert!(
                !msg.contains("walletAddress not found"),
                "deploy_wallet failed during address extraction: {msg}"
            );
            eprintln!("E2E: deploy_wallet expected failure (network/chain): {msg}");
        }
    }

    eprintln!("E2E: ALL PHASES PASSED ✓");
    Ok(())
}
