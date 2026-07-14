// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Shared application state.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

use crate::client::memory::MemoryClient;
use crate::client::object_store::ObjectStoreClient;
use crate::client::sealed_secrets::SealedSecretsClient;
use crate::config::NetworkConfig;
use crate::filter::engine::AbiRegistry;
use crate::filter::rules::FilterConfig;
use crate::mcp::tools::TxRateLimiter;

/// Error for a Memory-backed tool invoked in AI-Registry read-only mode.
fn memory_required() -> anyhow::Error {
    anyhow!(
        "Memory-backed mode required — this tool needs gosh.memory (wallet keys / \
         sealed secrets / wallet policies / fact ingest / pointer cache), but the \
         service is running in AI Registry read-only mode. Restart without --read-only \
         (with gosh.memory bootstrap/auth) to use it."
    )
}

/// How the service is exposed — determines the MCP tool surface and whether
/// gosh.memory is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    /// Full Memory-backed agent: every tool; gosh.memory required.
    Full,
    /// AI Registry read-only: no gosh.memory; chain-first read tools only.
    ReadOnly,
    /// Stateless user-signed payments: no gosh.memory and no keys — read tools
    /// plus payment-intent preparation / readiness verification (Flow A). Tools
    /// only PREPARE payloads the user's own wallet signs; they never accept,
    /// resolve, or store private keys.
    StatelessPayments,
}

pub struct AppState {
    pub filter_config: Mutex<FilterConfig>,
    pub abi_registry: Mutex<AbiRegistry>,
    /// gosh.memory clients — `None` in any no-Memory mode (read-only / stateless
    /// payments). Access them via [`AppState::memory_client`] /
    /// [`AppState::object_store`] / [`AppState::sealed_secrets`], which return an
    /// explicit "Memory-backed mode required" error when absent.
    memory_client: Option<MemoryClient>,
    object_store: Option<ObjectStoreClient>,
    sealed_secrets: Option<SealedSecretsClient>,
    /// How this instance is exposed (tool surface + Memory requirement).
    mode: ServeMode,
    pub network: NetworkConfig,
    pub tx_rate_limiter: TxRateLimiter,
    /// Shared HTTP client for outbound requests (wallet queries, etc.).
    pub http: reqwest::Client,
    /// Per-treasury serialization for `airegistry_fund_buyer`: the whole
    /// preflight → submit → poll window holds the treasury's lock, so two
    /// in-process top-ups against the same treasury can't race each other's
    /// queued-transaction correlation.
    pub fund_buyer_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl AppState {
    /// Full-agent mode: gosh.memory is wired up (wallets, secrets, policies,
    /// fact ingest, pointer cache).
    pub fn new(
        memory_client: MemoryClient,
        object_store: ObjectStoreClient,
        sealed_secrets: SealedSecretsClient,
        network: NetworkConfig,
    ) -> Self {
        Self {
            filter_config: Mutex::new(FilterConfig::default()),
            abi_registry: Mutex::new(AbiRegistry::new()),
            memory_client: Some(memory_client),
            object_store: Some(object_store),
            sealed_secrets: Some(sealed_secrets),
            mode: ServeMode::Full,
            network,
            tx_rate_limiter: TxRateLimiter::new(),
            http: reqwest::Client::new(),
            fund_buyer_locks: Mutex::new(HashMap::new()),
        }
    }

    /// AI Registry read-only mode: no gosh.memory. Only chain-first read tools
    /// are served; any Memory-backed tool returns "Memory-backed mode required".
    pub fn new_read_only(network: NetworkConfig) -> Self {
        Self::no_memory(ServeMode::ReadOnly, network)
    }

    /// Stateless user-signed payments mode: no gosh.memory and no keys. Read
    /// tools plus payment-intent preparation / readiness verification.
    pub fn new_stateless_payments(network: NetworkConfig) -> Self {
        Self::no_memory(ServeMode::StatelessPayments, network)
    }

    fn no_memory(mode: ServeMode, network: NetworkConfig) -> Self {
        Self {
            filter_config: Mutex::new(FilterConfig::default()),
            abi_registry: Mutex::new(AbiRegistry::new()),
            memory_client: None,
            object_store: None,
            sealed_secrets: None,
            mode,
            network,
            tx_rate_limiter: TxRateLimiter::new(),
            http: reqwest::Client::new(),
            fund_buyer_locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn mode(&self) -> ServeMode {
        self.mode
    }

    /// `true` in any no-Memory mode (read-only or stateless payments) — used to
    /// fail Memory-backed paths closed and to keep `call_contract` getter-only.
    pub fn is_read_only(&self) -> bool {
        self.mode != ServeMode::Full
    }

    pub fn memory_client(&self) -> Result<&MemoryClient> {
        self.memory_client.as_ref().ok_or_else(memory_required)
    }

    pub fn object_store(&self) -> Result<&ObjectStoreClient> {
        self.object_store.as_ref().ok_or_else(memory_required)
    }

    pub fn sealed_secrets(&self) -> Result<&SealedSecretsClient> {
        self.sealed_secrets.as_ref().ok_or_else(memory_required)
    }
}
