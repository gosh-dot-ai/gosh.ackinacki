// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

use std::net::SocketAddr;

use clap::Parser;
use serde::{Deserialize, Serialize};

/// AI Registry (airegistry / SPC token contracts) per-network configuration.
///
/// These are **mutable config**, not a permanent pin: upstream airegistry lives
/// on an ephemeral branch today and will migrate. When it moves, bump these
/// values; if they drift from chain, the airegistry tests fail — that is the
/// intended signal. The embedded ABIs/TVCs (see `crate::airegistry::abi`) are a
/// self-contained snapshot, checked against these code hashes at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRegistryConfig {
    /// Canonical SuperRoot for this network. None = "deploy-if-missing in tests".
    pub super_root_address: Option<String>,
    pub super_root_pubkey: Option<String>,
    /// Code hashes that MUST match the embedded TVCs (and the on-chain constants).
    pub root_model_code_hash: String,
    pub manifest_metadata_code_hash: String,
    pub token_contract_code_hash: String,
    /// Giver (shellnet test funding). None on mainnet.
    pub giver_address: Option<String>,
    pub giver_pubkey: Option<String>,
    /// Giver signing secret (shellnet public test key only; None elsewhere).
    /// Lets airegistry deploy tools fund fresh derived addresses on shellnet
    /// per §8. Never set on mainnet/custom — those must fund another way.
    pub giver_secret: Option<String>,
    /// DApp id rule for GraphQL `account(account_id, dapp_id)` BOC reads.
    /// None ⇒ default rule (self-originating airegistry account ⇒ dapp_id ==
    /// account_id). A value forces this dapp_id; always overridable per call.
    pub dapp_id_override: Option<String>,
}

impl AiRegistryConfig {
    /// shellnet airegistry config (code hashes from gosh-sh/acki-nacki@86d1dec3).
    pub fn shellnet() -> Self {
        Self {
            super_root_address: None,
            super_root_pubkey: None,
            root_model_code_hash:
                "49bff1b40eb044ea790822a2a2a1b01515b8ab8d92f3699584407b01c831e2aa".into(),
            manifest_metadata_code_hash:
                "537fc452f2514c56a831f67d265b478a969e42a3597ae78abb7552efbc4420e1".into(),
            token_contract_code_hash:
                "9940e7142004d9643317543e5e6c5aaaae39757a6a264ce645ade660a6539c88".into(),
            giver_address: Some(
                "0:1111111111111111111111111111111111111111111111111111111111111111".into(),
            ),
            giver_pubkey: Some(
                "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c".into(),
            ),
            giver_secret: Some(
                "fdf96f7cc288cfbd48a645e86942e938e814a91dc1c17a98a4e04f619c07cc0b".into(),
            ),
            dapp_id_override: None,
        }
    }

    /// mainnet placeholder — airegistry not deployed there yet; hashes mirror
    /// shellnet until a mainnet build exists. No Giver on mainnet.
    pub fn mainnet() -> Self {
        Self {
            super_root_address: None,
            super_root_pubkey: None,
            giver_address: None,
            giver_pubkey: None,
            giver_secret: None,
            ..Self::shellnet()
        }
    }

    /// Neutral config for `custom` networks: the code hashes match the embedded
    /// TVCs (so the hash-lock still works for the vendored artifacts), but the
    /// network-specific fields fail **closed** — no SuperRoot, and crucially
    /// **no shellnet test Giver**. Operators of a custom network must supply
    /// `super_root_address` and (if used) `giver_*` explicitly; airegistry tools
    /// that need a Giver/SuperRoot will error until those are provided rather
    /// than silently inheriting shellnet assumptions.
    pub fn custom() -> Self {
        Self {
            super_root_address: None,
            super_root_pubkey: None,
            giver_address: None,
            giver_pubkey: None,
            giver_secret: None,
            dapp_id_override: None,
            ..Self::shellnet() // only the embedded-artifact code hashes are inherited
        }
    }
}

/// Well-known network configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    /// QUIC endpoints for block stream (BK nodes).
    /// CLI --bk-nodes accepts SocketAddr (IP:port).
    /// Preset configs use hostnames resolved at connect time.
    pub bk_nodes: Vec<SocketAddr>,
    /// BK node hostnames (for presets that need DNS resolution).
    pub bk_hostnames: Vec<String>,
    /// HTTP endpoint for sending external messages.
    pub send_endpoint: String,
    /// DappRoot system address (0:999...9 on all networks).
    pub dapp_root: String,
    /// AI Registry (SPC token) config for this network.
    pub airegistry: AiRegistryConfig,
}

impl NetworkConfig {
    pub fn shellnet() -> Self {
        Self {
            name: "shellnet".into(),
            bk_nodes: vec![],
            bk_hostnames: vec![
                "shellnet0.ackinacki.org:10000".into(),
                "shellnet1.ackinacki.org:10000".into(),
                "shellnet2.ackinacki.org:10000".into(),
                "shellnet3.ackinacki.org:10000".into(),
                "shellnet4.ackinacki.org:10000".into(),
            ],
            send_endpoint: "https://shellnet.ackinacki.org".into(),
            dapp_root: "0:9999999999999999999999999999999999999999999999999999999999999999".into(),
            airegistry: AiRegistryConfig::shellnet(),
        }
    }

    pub fn mainnet() -> Self {
        Self {
            name: "mainnet".into(),
            bk_nodes: vec![],
            bk_hostnames: vec![],
            send_endpoint: "https://mainnet.ackinacki.org".into(),
            dapp_root: "0:9999999999999999999999999999999999999999999999999999999999999999".into(),
            airegistry: AiRegistryConfig::mainnet(),
        }
    }

    pub fn custom(name: &str, bk_nodes: Vec<SocketAddr>, send_endpoint: &str) -> Self {
        Self {
            name: name.into(),
            bk_nodes,
            bk_hostnames: vec![],
            send_endpoint: send_endpoint.into(),
            dapp_root: "0:9999999999999999999999999999999999999999999999999999999999999999".into(),
            airegistry: AiRegistryConfig::custom(),
        }
    }

    /// Resolve hostnames to SocketAddrs. Call at startup.
    pub async fn resolve_hostnames(&mut self) -> anyhow::Result<()> {
        for hostname in &self.bk_hostnames {
            match tokio::net::lookup_host(hostname).await {
                Ok(addrs) => {
                    if let Some(addr) = addrs.into_iter().next() {
                        self.bk_nodes.push(addr);
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to resolve {hostname}: {e}");
                }
            }
        }
        Ok(())
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Network {
    Shellnet,
    Mainnet,
    Custom,
}

#[derive(Parser, Debug)]
#[command(
    name = "gosh-ackinacki",
    about = "Acki Nacki blockchain integration for GOSH.AI"
)]
pub struct Cli {
    /// MCP server bind address.
    ///
    /// TLS is not handled by this binary. In production, terminate TLS at a
    /// reverse proxy (e.g. nginx, Caddy, or a cloud load balancer) in front
    /// of gosh-ackinacki.  Binding to a non-localhost address without TLS
    /// will emit a startup warning.
    #[arg(long, default_value = "127.0.0.1:8402", env = "GOSH_ACKINACKI_BIND")]
    pub bind: SocketAddr,

    /// Network: shellnet, mainnet, or custom
    #[arg(long, default_value = "shellnet", env = "GOSH_ACKINACKI_NETWORK")]
    pub network: Network,

    /// BK node QUIC addresses (comma-separated, overrides network defaults)
    #[arg(long, env = "GOSH_ACKINACKI_BK_NODES", value_delimiter = ',')]
    pub bk_nodes: Vec<SocketAddr>,

    /// HTTP endpoint for sending messages (overrides network default)
    #[arg(long, env = "GOSH_ACKINACKI_SEND_ENDPOINT")]
    pub send_endpoint: Option<String>,

    /// Default AI Registry SuperRoot address for this network. Lets read-only
    /// marketplace clients (e.g. a backend indexer) call
    /// `airegistry_list_marketplace` without knowing the deployment's SuperRoot.
    #[arg(long, env = "GOSH_AIREGISTRY_SUPER_ROOT")]
    pub airegistry_super_root: Option<String>,

    /// gosh.memory base URL
    #[arg(long, default_value = "http://127.0.0.1:8000", env = "GOSH_MEMORY_URL")]
    pub memory_url: String,

    /// gosh.memory instance key
    #[arg(long, default_value = "default", env = "GOSH_MEMORY_KEY")]
    pub memory_key: String,

    /// Agent ID for gosh.memory
    #[arg(long, default_value = "ackinacki", env = "GOSH_AGENT_ID")]
    pub agent_id: String,

    /// Swarm ID for gosh.memory
    #[arg(long, default_value = "default", env = "GOSH_SWARM_ID")]
    pub swarm_id: String,

    /// Optional transport token (x-server-token perimeter header) for gosh.memory.
    #[arg(long, default_value = "", env = "GOSH_MEMORY_TRANSPORT_TOKEN")]
    pub memory_transport_token: String,

    /// MCP server token (x-server-token auth). Auto-generated if not set.
    #[arg(long, env = "GOSH_ACKINACKI_SERVER_TOKEN")]
    pub server_token: Option<String>,

    /// Filter config JSON file (optional)
    #[arg(long, env = "GOSH_ACKINACKI_FILTER")]
    pub filter_config: Option<String>,

    /// Bootstrap file containing {join_token, secret_key}. Consumed and deleted
    /// on first successful start; subsequent restarts reuse the persisted
    /// memory-auth.json from --memory-auth-path.
    #[arg(long, env = "GOSH_ACKINACKI_BOOTSTRAP")]
    pub bootstrap_file: Option<String>,

    /// Path to memory-auth.json (Bearer principal token persistence).
    /// Defaults to $HOME/.gosh-ackinacki/memory-auth.json.
    #[arg(long, env = "GOSH_ACKINACKI_MEMORY_AUTH_PATH")]
    pub memory_auth_path: Option<String>,

    /// Start in AI Registry READ-ONLY mode: no gosh.memory needed. Serves only
    /// the chain-first AI Registry read tools (manifest/lot/model/entitlement/
    /// discovery); wallet/secret/policy/fact-ingest tools return
    /// "Memory-backed mode required". No bootstrap/auth/Memory instance required.
    #[arg(long, env = "GOSH_ACKINACKI_READ_ONLY")]
    pub read_only: bool,

    /// Start in STATELESS user-signed PAYMENTS mode: like --read-only (no
    /// gosh.memory), plus the payment-intent preparation / readiness tools
    /// (`airegistry_prepare_user_buy_tokens` / `_prepare_user_cancel` /
    /// `_verify_payment_readiness`). These only PREPARE payloads the user's own
    /// wallet signs — they never accept, resolve, or store private keys.
    #[arg(long, env = "GOSH_ACKINACKI_STATELESS_PAYMENTS")]
    pub stateless_payments: bool,
}

impl Cli {
    /// Resolve network config: CLI args override network defaults.
    pub fn resolve_network(&self) -> NetworkConfig {
        let mut net = match self.network {
            Network::Shellnet => NetworkConfig::shellnet(),
            Network::Mainnet => NetworkConfig::mainnet(),
            Network::Custom => NetworkConfig::custom("custom", vec![], ""),
        };

        // CLI overrides
        if !self.bk_nodes.is_empty() {
            net.bk_nodes = self.bk_nodes.clone();
        }
        if let Some(ref ep) = self.send_endpoint {
            net.send_endpoint = ep.clone();
        }
        if let Some(ref sr) = self.airegistry_super_root {
            if !sr.is_empty() {
                net.airegistry.super_root_address = Some(sr.clone());
            }
        }

        net
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellnet_config_defaults() {
        let net = NetworkConfig::shellnet();
        assert_eq!(net.name, "shellnet");
        assert!(net.send_endpoint.contains("shellnet"));
        assert!(net.dapp_root.starts_with("0:9999"));
    }

    #[test]
    fn shellnet_airegistry_has_giver() {
        let air = NetworkConfig::shellnet().airegistry;
        assert!(air.giver_address.as_deref().unwrap().starts_with("0:1111"));
        assert!(air.giver_pubkey.is_some());
    }

    #[test]
    fn custom_airegistry_fails_closed_no_giver_or_superroot() {
        // Regression guard: custom must NOT inherit the shellnet test Giver
        // key or SuperRoot — operators supply those explicitly.
        let air = NetworkConfig::custom("dev", vec![], "http://localhost").airegistry;
        assert!(air.giver_address.is_none(), "custom must not carry a Giver");
        assert!(air.giver_pubkey.is_none());
        assert!(air.super_root_address.is_none());
        // Code hashes still present (they bind the embedded artifacts).
        assert_eq!(air.token_contract_code_hash.len(), 64);
    }

    #[test]
    fn custom_airegistry_hashes_match_embedded() {
        // The custom network's code hashes still verify against the embedded
        // TVCs (the hash-lock works regardless of network).
        let air = NetworkConfig::custom("dev", vec![], "http://x").airegistry;
        crate::airegistry::abi::verify_code_hashes(&air).unwrap();
    }

    #[test]
    fn mainnet_config_defaults() {
        let net = NetworkConfig::mainnet();
        assert_eq!(net.name, "mainnet");
        assert!(!net.send_endpoint.contains("shellnet"));
    }

    #[test]
    fn custom_config() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let net = NetworkConfig::custom("dev", vec![addr], "http://localhost:8080");
        assert_eq!(net.name, "dev");
        assert_eq!(net.bk_nodes.len(), 1);
        assert_eq!(net.send_endpoint, "http://localhost:8080");
    }

    #[test]
    fn dapp_root_is_consistent() {
        let t = NetworkConfig::shellnet();
        let m = NetworkConfig::mainnet();
        assert_eq!(t.dapp_root, m.dapp_root);
    }

    #[test]
    fn shellnet_has_hostnames() {
        let net = NetworkConfig::shellnet();
        assert_eq!(net.bk_hostnames.len(), 5);
        assert!(net.bk_hostnames[0].contains("shellnet0"));
        // bk_nodes empty until resolve_hostnames() is called
        assert!(net.bk_nodes.is_empty());
    }

    #[test]
    fn custom_has_no_hostnames() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let net = NetworkConfig::custom("dev", vec![addr], "http://localhost:8080");
        assert!(net.bk_hostnames.is_empty());
    }
}
