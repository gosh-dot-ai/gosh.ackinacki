// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use gosh_ackinacki::client::auth::{
    default_memory_auth_path, BootstrapData, JoinToken, MemoryAuthState,
};
use gosh_ackinacki::client::memory::MemoryClient;
use gosh_ackinacki::client::object_store::ObjectStoreClient;
use gosh_ackinacki::client::sealed_secrets::SealedSecretsClient;
use gosh_ackinacki::config::Cli;
use gosh_ackinacki::filter::rules::FilterConfig;
use gosh_ackinacki::mcp;
use gosh_ackinacki::state::AppState;

// Block-stream indexer (feature-gated): channels + node/transport/decoder.
#[cfg(feature = "block-stream")]
use gosh_ackinacki::decoder::block;
#[cfg(feature = "block-stream")]
use gosh_ackinacki::filter::engine;
#[cfg(feature = "block-stream")]
use gosh_ackinacki::transform;
#[cfg(feature = "block-stream")]
use gosh_ackinacki::transport;
#[cfg(feature = "block-stream")]
use gosh_ackinacki::BlockCommand;
#[cfg(feature = "block-stream")]
use std::sync::mpsc;
#[cfg(feature = "block-stream")]
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,gosh_ackinacki=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    // Load filter config if provided (both modes).
    let initial_filter = if let Some(ref path) = cli.filter_config {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str::<FilterConfig>(&data)?
    } else {
        FilterConfig::default()
    };

    // No-Memory modes: AI Registry read-only, or stateless user-signed payments.
    let no_memory = cli.read_only || cli.stateless_payments;

    // Resolve network config (both modes).
    let mut network = cli.resolve_network();
    // BK hostname (DNS) resolution is only for the full-mode block stream's QUIC
    // pool; a no-Memory service needs only the HTTP/GraphQL send endpoint, so
    // skip it (no BK/DNS startup dependency before MCP is up).
    if !no_memory {
        network.resolve_hostnames().await.ok();
    }
    tracing::info!(
        network = network.name,
        send_endpoint = network.send_endpoint,
        bk_nodes = network.bk_nodes.len(),
        read_only = cli.read_only,
        stateless_payments = cli.stateless_payments,
        "network config resolved",
    );

    // Fail-fast: the embedded airegistry TVCs MUST match the configured code
    // hashes (the off-chain mirror of the contracts' on-chain code-hash lock).
    gosh_ackinacki::airegistry::abi::verify_code_hashes(&network.airegistry)
        .context("airegistry embedded artifact code-hash verification failed at startup")?;
    tracing::info!("airegistry code-hash lock verified (embedded TVCs match config)");

    let http = reqwest::Client::new();

    // Mode split: AI Registry READ-ONLY (chain-first, no gosh.memory) vs the
    // full Memory-backed agent (wallets/secrets/policies/fact ingest/cache).
    type Handles = (
        Arc<AppState>,
        Option<tokio::task::JoinHandle<()>>,
        Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)>,
    );
    let (state, ingest_handle, stream_handle): Handles = if no_memory {
        let state = if cli.stateless_payments {
            tracing::info!(
                "STATELESS PAYMENTS mode: no gosh.memory and no keys; serves chain-first read \
                 tools plus payment-intent preparation / readiness verification. These only \
                 PREPARE payloads the user's own wallet signs — never key material."
            );
            Arc::new(AppState::new_stateless_payments(network.clone()))
        } else {
            tracing::info!(
                "AI Registry READ-ONLY mode: no gosh.memory; only chain-first read tools are served \
                 (manifest / lot / model / entitlement / discovery). Memory-backed tools \
                 (wallets / secrets / policies / fact ingest) return 'Memory-backed mode required'."
            );
            Arc::new(AppState::new_read_only(network.clone()))
        };
        *state.filter_config.lock() = initial_filter;
        (state, None, None)
    } else {
        // Resolve auth (bootstrap → memory-auth.json → X25519 secret).
        let memory_auth_path = cli
            .memory_auth_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(default_memory_auth_path);
        let AuthBundle {
            auth_state,
            x25519_secret,
        } = resolve_auth(&cli, &memory_auth_path)?;
        let principal_token = auth_state.principal_token.clone().ok_or_else(|| {
            anyhow!("memory-auth has no principal_token — re-bootstrap with --bootstrap-file (or start with --read-only for a no-Memory AI Registry read service)")
        })?;
        let transport_token = auth_state
            .transport_token
            .clone()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                if cli.memory_transport_token.is_empty() {
                    None
                } else {
                    Some(cli.memory_transport_token.clone())
                }
            });
        let memory_url = auth_state.memory_url.clone();

        let memory_client = MemoryClient::new(
            &memory_url,
            &cli.memory_key,
            &cli.agent_id,
            &cli.swarm_id,
            &principal_token,
        )
        .with_transport_token(transport_token.as_deref());
        let object_store = ObjectStoreClient::new(
            http.clone(),
            &memory_url,
            &principal_token,
            transport_token.as_deref(),
            &cli.memory_key,
            &cli.swarm_id,
            &cli.agent_id,
        );
        let sealed_secrets = SealedSecretsClient::new(
            http.clone(),
            &memory_url,
            &principal_token,
            transport_token.as_deref(),
            &cli.memory_key,
            Arc::new(x25519_secret),
        );

        // Register our X25519 public key with gosh.memory (idempotent).
        if let Err(e) = sealed_secrets.register_public_key().await {
            tracing::warn!(
                "X25519 pubkey registration failed (sealed secret resolve will not work): {e}"
            );
        } else {
            tracing::info!("registered X25519 public key with gosh.memory");
        }

        let state = Arc::new(AppState::new(
            memory_client,
            object_store,
            sealed_secrets,
            network.clone(),
        ));
        *state.filter_config.lock() = initial_filter;

        // Block stream → decoder → ingest pipeline (full mode, `block-stream` feature).
        #[cfg(feature = "block-stream")]
        {
            let (cmd_tx, cmd_rx) = mpsc::channel::<BlockCommand>();
            let (nodes_tx, nodes_rx) = watch::channel(network.bk_nodes.clone());
            let _ = nodes_tx;
            let (ingest_tx, mut ingest_rx) =
                tokio::sync::mpsc::channel::<Vec<transform::BlockchainFact>>(64);

            let ingest_client = state.memory_client()?.clone();
            let ingest_handle = tokio::spawn(async move {
                while let Some(facts) = ingest_rx.recv().await {
                    if let Err(e) = ingest_client.ingest_facts(&facts).await {
                        tracing::error!("memory ingest failed: {e}");
                    }
                }
            });

            let stream_state = state.clone();
            let nodes = network.bk_nodes.clone();
            let stream_handle = if !nodes.is_empty() {
                let pool_handle = tokio::spawn(async move {
                    if let Err(e) = transport::pool::run(nodes, cmd_tx, nodes_rx).await {
                        tracing::warn!("transport pool exited: {e}");
                    }
                });
                let decoder_handle = tokio::task::spawn_blocking(move || {
                    let session_counter = std::sync::atomic::AtomicI64::new(1);
                    let r = block::run(cmd_rx, |decoded| {
                        let config = stream_state.filter_config.lock().clone();
                        let abi_reg = stream_state.abi_registry.lock();
                        let matched = engine::process_block(&decoded, &config, &abi_reg);
                        drop(abi_reg);
                        if matched.is_empty() {
                            return Ok(());
                        }
                        let session_num =
                            session_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let session_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
                        let facts: Vec<_> = matched
                            .iter()
                            .map(|m| transform::to_fact(m, session_num, &session_date))
                            .collect();
                        tracing::info!(
                            count = facts.len(),
                            block = matched[0].block_seq_no,
                            "injecting facts into gosh.memory"
                        );
                        if ingest_tx.blocking_send(facts).is_err() {
                            tracing::error!("ingestion channel closed");
                        }
                        Ok(())
                    });
                    if let Err(e) = r {
                        tracing::warn!("block decoder exited: {e}");
                    }
                });
                Some((pool_handle, decoder_handle))
            } else {
                tracing::warn!("no BK nodes configured, block stream disabled");
                None
            };
            (state, Some(ingest_handle), stream_handle)
        }
        #[cfg(not(feature = "block-stream"))]
        {
            tracing::info!(
                "full-agent mode built WITHOUT the `block-stream` feature — serving MCP + \
                 gosh.memory, but NOT ingesting the BK block firehose. Rebuild with \
                 `--features block-stream` to enable block ingestion."
            );
            (state, None, None)
        }
    };

    // Generate or use provided MCP server token (perimeter auth on the MCP HTTP endpoint).
    let server_token = cli.server_token.unwrap_or_else(|| {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect()
    });
    tracing::info!(
        token_prefix = &server_token[..4.min(server_token.len())],
        "MCP server token generated (use x-server-token header)"
    );
    let token_path = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".gosh-ackinacki")
        .join("token");
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Perimeter credential: write privately + atomically — the file is created
    // with mode 0o600 up front (no world-readable umask window) then renamed
    // into place, matching MemoryAuthState::save().
    if let Err(e) =
        gosh_ackinacki::client::auth::write_private_text_file(&token_path, &server_token)
    {
        tracing::warn!("could not save token to {}: {e}", token_path.display());
    } else {
        tracing::info!(path = %token_path.display(), "server token saved to file");
    }

    let bind = cli.bind;
    let mcp_state = state.clone();
    let mcp_token = server_token.clone();
    tracing::info!("starting gosh-ackinacki MCP server");
    let mcp_handle = tokio::spawn(async move { mcp::serve(bind, mcp_state, &mcp_token).await });

    tokio::select! {
        r = mcp_handle => {
            tracing::info!("MCP server exited: {r:?}");
        }
        // Ingest task only exists in full mode.
        _ = async {
            if let Some(h) = ingest_handle {
                let r = h.await;
                tracing::warn!("ingestion task exited: {r:?}");
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        // Block stream only exists in full mode (with BK nodes).
        _ = async {
            if let Some((pool, decoder)) = stream_handle {
                tokio::select! {
                    r = pool => tracing::warn!("pool exited: {r:?}"),
                    r = decoder => tracing::warn!("decoder exited: {r:?}"),
                }
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }

    Ok(())
}

struct AuthBundle {
    auth_state: MemoryAuthState,
    x25519_secret: StaticSecret,
}

/// Load auth + X25519 secret from either bootstrap file (first run) or
/// persisted memory-auth.json (subsequent runs).
fn resolve_auth(cli: &Cli, memory_auth_path: &std::path::Path) -> anyhow::Result<AuthBundle> {
    if let Some(ref boot_path) = cli.bootstrap_file {
        let boot_path = PathBuf::from(boot_path);
        let bootstrap = BootstrapData::read(&boot_path)?;
        let mut key_bytes = bootstrap.decode_secret_key()?;
        let secret = StaticSecret::from(key_bytes);
        key_bytes.zeroize();

        let join = JoinToken::decode(&bootstrap.join_token)?;
        let auth_state = MemoryAuthState::from_join(join);
        auth_state
            .save(memory_auth_path)
            .with_context(|| format!("persisting memory-auth at {}", memory_auth_path.display()))?;
        if let Err(e) = std::fs::remove_file(&boot_path) {
            tracing::warn!(
                "could not delete bootstrap file {}: {e}",
                boot_path.display()
            );
        } else {
            tracing::info!(
                bootstrap_file = %boot_path.display(),
                "bootstrap consumed and deleted; auth persisted to {}",
                memory_auth_path.display()
            );
        }
        return Ok(AuthBundle {
            auth_state,
            x25519_secret: secret,
        });
    }

    // No bootstrap → fall back to existing memory-auth.json, but we still need
    // the X25519 secret. We expect the operator to provide it via
    // GOSH_ACKINACKI_X25519_SECRET (base64 32 bytes) for restarts.
    let auth_state = MemoryAuthState::load(memory_auth_path)?.ok_or_else(|| {
        anyhow!(
            "neither --bootstrap-file nor existing {} present; cannot start",
            memory_auth_path.display()
        )
    })?;

    let secret_b64 = std::env::var("GOSH_ACKINACKI_X25519_SECRET").map_err(|_| {
        anyhow!(
            "GOSH_ACKINACKI_X25519_SECRET (base64 of 32-byte X25519 private key) is required \
             on restart when --bootstrap-file is not provided"
        )
    })?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.trim())
        .context("decoding GOSH_ACKINACKI_X25519_SECRET")?;
    if bytes.len() != 32 {
        bail!(
            "GOSH_ACKINACKI_X25519_SECRET must be exactly 32 bytes (got {})",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let secret = StaticSecret::from(arr);
    arr.zeroize();

    Ok(AuthBundle {
        auth_state,
        x25519_secret: secret,
    })
}
