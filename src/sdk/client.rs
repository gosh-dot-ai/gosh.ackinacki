// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! [`ChainClient`] — a lean chain handle over the Block Manager HTTP/GraphQL API
//! (Plane A): account reads with balances, local ABI getters, signed external
//! calls + deploys, and a block-production liveness probe. No `node`, no MsQuic.
//!
//! Every method is a thin wrapper over the existing layers
//! ([`crate::airegistry::getter`], [`crate::airegistry::run`],
//! [`crate::airegistry::calls`], [`crate::wallet::query`]) — no logic is moved.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use futures_util::stream::Stream;
use serde_json::Value;
use tvm_client::ClientContext;

use crate::airegistry::calls::encode_external_call;
use crate::airegistry::deploy::{local_context, DeployMessage};
use crate::airegistry::getter::{AccountOrigin, AccountReader, ChainLiveness, EventRecord};
use crate::airegistry::run::{read_getter, GetterRunner};
use crate::config::{AiRegistryConfig, NetworkConfig};
use crate::wallet::query::send_message;

use super::keys::KeyPair;
use super::types::Address;

/// ECC[2] SHELL extra-currency id.
const SHELL_ECC_ID: u32 = 2;

/// An account snapshot with balances: status, native VMSHELL, extra currencies
/// (ECC), code hash, and the raw BOC.
#[derive(Debug, Clone)]
pub struct Account {
    pub address: Address,
    /// `Uninit` | `Active` | `Frozen` | `NonExist`.
    pub status: String,
    /// Native VMSHELL balance (nanotokens).
    pub balance: u128,
    /// Extra currencies as `(currency_id, value)` — e.g. ECC[2] is SHELL.
    pub ecc: Vec<(u32, u128)>,
    /// Code hash (hex), present when the account has code.
    pub code_hash: Option<String>,
    /// Account BOC (base64), present when the account exists.
    pub boc: Option<String>,
}

impl Account {
    pub fn is_active(&self) -> bool {
        self.status == "Active"
    }

    /// ECC[2] SHELL balance (0 if absent).
    pub fn shell(&self) -> u128 {
        self.ecc_balance(SHELL_ECC_ID)
    }

    /// Balance of extra currency `id` (0 if absent).
    pub fn ecc_balance(&self, id: u32) -> u128 {
        self.ecc
            .iter()
            .find(|(cid, _)| *cid == id)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
}

/// A lean chain client over the Block Manager HTTP/GraphQL API (Plane A).
/// Construct with [`ChainClient::connect`], [`ChainClient::connect_with_config`],
/// [`ChainClient::connect_network`], or [`ChainClient::shellnet`].
#[derive(Clone)]
pub struct ChainClient {
    http: reqwest::Client,
    reader: AccountReader,
    runner: GetterRunner,
    ctx: Arc<ClientContext>,
    endpoint: String,
    cfg: AiRegistryConfig,
}

impl ChainClient {
    /// Connect to a Block Manager HTTP endpoint with generic/custom AI Registry
    /// config. Use [`ChainClient::shellnet`] for shellnet presets or
    /// [`ChainClient::connect_with_config`] when the endpoint has a known
    /// AI Registry deployment.
    pub fn connect(endpoint: &str) -> Result<Self> {
        Self::connect_with_config(endpoint, AiRegistryConfig::custom())
    }

    /// Connect to a Block Manager HTTP endpoint with explicit AI Registry
    /// config. This keeps endpoint and per-network contract config from
    /// silently diverging.
    pub fn connect_with_config(endpoint: &str, cfg: AiRegistryConfig) -> Result<Self> {
        let http = reqwest::Client::new();
        Ok(Self {
            reader: AccountReader::new(http.clone(), endpoint),
            runner: GetterRunner::new()?,
            ctx: local_context()?,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            cfg,
            http,
        })
    }

    /// Connect with a full network preset/custom config.
    pub fn connect_network(network: NetworkConfig) -> Result<Self> {
        Self::connect_with_config(&network.send_endpoint, network.airegistry)
    }

    /// Connect to Acki Nacki shellnet.
    pub fn shellnet() -> Result<Self> {
        Self::connect_network(NetworkConfig::shellnet())
    }

    /// The HTTP endpoint this client targets.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Probe chain liveness (newest block age vs the BM clock) — tells a halted
    /// network apart from a bad write. Stale threshold 60s.
    pub async fn chain_liveness(&self) -> Result<ChainLiveness> {
        self.reader.chain_liveness(60).await
    }

    /// Fetch an account with native + ECC balances. `Ok(None)` if not found.
    /// Queries with `dapp_id == account_id` (self-originating); for a DApp child
    /// account pass its dapp via [`ChainClient::get_account_in_dapp`].
    pub async fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        self.get_account_in_dapp(address, address).await
    }

    /// Like [`ChainClient::get_account`] but with an explicit `dapp` account — a
    /// DApp child wallet inherits its SwarmRoot's dapp id rather than its own.
    pub async fn get_account_in_dapp(
        &self,
        address: &Address,
        dapp: &Address,
    ) -> Result<Option<Account>> {
        let q = format!(
            "{{ blockchain {{ account(account_id: \"{}\", dapp_id: \"{}\") {{ info {{ \
             acc_type_name boc code_hash balance balance_other {{ currency value }} }} }} }} }}",
            address.bare(),
            dapp.bare(),
        );
        let url = self.reader.graphql_url();
        let resp: Value = self
            .http
            .post(url)
            .json(&serde_json::json!({ "query": q }))
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()?
            .json()
            .await
            .context("parse account response")?;
        if let Some(e) = resp.get("errors") {
            if !e.is_null() {
                return Err(anyhow!("GraphQL errors: {e}"));
            }
        }
        let info = match resp.pointer("/data/blockchain/account/info") {
            Some(i) if !i.is_null() => i,
            _ => return Ok(None),
        };
        let mut ecc = Vec::new();
        if let Some(arr) = info.get("balance_other").and_then(|v| v.as_array()) {
            for c in arr {
                let id = c
                    .get("currency")
                    .ok_or_else(|| anyhow!("account balance_other entry missing currency"))
                    .and_then(value_as_u32)?;
                let val = c
                    .get("value")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("account balance_other[{id}] missing value"))
                    .and_then(parse_hex_u128)?;
                ecc.push((id, val));
            }
        }
        let balance = info
            .get("balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("account response missing balance"))
            .and_then(parse_hex_u128)?;
        Ok(Some(Account {
            address: address.clone(),
            status: info
                .get("acc_type_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            balance,
            ecc,
            code_hash: info
                .get("code_hash")
                .and_then(|v| v.as_str())
                .map(String::from),
            boc: info.get("boc").and_then(|v| v.as_str()).map(String::from),
        }))
    }

    /// Run an ABI getter locally against the account's fetched BOC (no tx, no
    /// signature). `Ok(None)` if the account is not active.
    pub async fn run_getter(
        &self,
        address: &Address,
        abi_json: &str,
        method: &str,
        args: Value,
    ) -> Result<Option<Value>> {
        read_getter(
            &self.reader,
            &self.runner,
            &self.cfg,
            abi_json,
            &address.with_workchain(),
            &AccountOrigin::SelfOriginating,
            method,
            args,
        )
        .await
    }

    /// Encode + send a signed external-inbound call, returning the Block Manager
    /// send response. A BM refusal (`QUEUE_OVERFLOW` on a halted chain, or a
    /// synchronous `TVM_ERROR` compute revert) is surfaced as `Err`.
    pub async fn call(
        &self,
        address: &Address,
        abi_json: &str,
        method: &str,
        args: Value,
        keys: &KeyPair,
    ) -> Result<Value> {
        let boc = encode_external_call(
            &self.ctx,
            abi_json,
            &address.with_workchain(),
            method,
            args,
            keys.public_hex(),
            keys.secret_hex(),
        )
        .await?;
        send_message(&self.http, &self.endpoint, &boc).await
    }

    /// Send a prebuilt deploy message (from
    /// [`crate::airegistry::deploy::build_deploy`]) and poll until the account is
    /// `Active`. Returns its [`Address`]. Errors if it doesn't activate within
    /// `timeout_secs`.
    pub async fn deploy(&self, msg: &DeployMessage, timeout_secs: u64) -> Result<Address> {
        let address = Address::parse(&msg.address)?;
        send_message(&self.http, &self.endpoint, &msg.message_boc_b64).await?;
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if let Some(acc) = self.get_account(&address).await? {
                if acc.is_active() {
                    return Ok(address);
                }
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "deploy {address} did not become Active within {timeout_secs}s"
                ));
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Subscribe to an account's decoded events as an async `Stream`. Pages
    /// forward through the event log (`read_events`) from the start; once caught
    /// up it waits `poll` and polls again, so the stream is effectively infinite
    /// and yields each new event as it appears. Each item is an [`EventRecord`]
    /// (decoded event + on-chain identity + a resume cursor for checkpointing);
    /// `page` bounds the per-poll page size. A transient read error is yielded as
    /// an `Err` item (rate-limited by `poll`) and the stream continues.
    ///
    /// Consume with `futures_util::StreamExt`:
    /// `let mut s = client.subscribe_events(&addr, abi, 50, Duration::from_secs(3));
    /// while let Some(ev) = s.next().await { … }`.
    pub fn subscribe_events(
        &self,
        address: &Address,
        abi_json: &str,
        page: u32,
        poll: Duration,
    ) -> impl Stream<Item = Result<EventRecord>> + 'static {
        let reader = self.reader.clone();
        let cfg = self.cfg.clone();
        let addr = address.with_workchain();
        let abi = abi_json.to_string();
        futures_util::stream::unfold(
            (None::<String>, VecDeque::<EventRecord>::new()),
            move |(mut cursor, mut buf)| {
                let reader = reader.clone();
                let cfg = cfg.clone();
                let addr = addr.clone();
                let abi = abi.clone();
                async move {
                    loop {
                        if let Some(rec) = buf.pop_front() {
                            return Some((Ok(rec), (cursor, buf)));
                        }
                        match reader
                            .read_events(
                                &cfg,
                                &addr,
                                &abi,
                                &AccountOrigin::SelfOriginating,
                                page,
                                cursor.as_deref(),
                            )
                            .await
                        {
                            Ok(p) => {
                                if let Some(c) = p.end_cursor {
                                    cursor = Some(c);
                                }
                                buf.extend(p.records);
                                if buf.is_empty() {
                                    // caught up — wait before polling again.
                                    tokio::time::sleep(poll).await;
                                }
                            }
                            Err(e) => {
                                // rate-limit a failing poll, then surface it.
                                tokio::time::sleep(poll).await;
                                return Some((Err(e), (cursor, buf)));
                            }
                        }
                    }
                }
            },
        )
    }
}

/// Parse a `0x`-prefixed (or bare) hex integer string into `u128`.
fn parse_hex_u128(s: &str) -> Result<u128> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    u128::from_str_radix(s, 16).with_context(|| format!("invalid hex u128 {s:?}"))
}

/// GraphQL serves `currency` as a JSON number (e.g. `2.0`); accept only exact
/// integer values that fit in u32.
fn value_as_u32(v: &Value) -> Result<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).context("currency id out of range");
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f.fract() == 0.0 && f >= 0.0 && f <= u32::MAX as f64 {
            return Ok(f as u32);
        }
    }
    Err(anyhow!("currency id must be an integer u32, got {v}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_u128_forms() {
        assert_eq!(
            parse_hex_u128("0x8ac7115f64315a48").unwrap(),
            0x8ac7115f64315a48
        );
        assert_eq!(parse_hex_u128("ff").unwrap(), 255);
        assert_eq!(parse_hex_u128("0x0").unwrap(), 0);
        assert!(parse_hex_u128("garbage").is_err());
    }

    #[test]
    fn connect_endpoint_does_not_silently_use_shellnet_config() {
        let custom = ChainClient::connect("https://custom.example.test/").unwrap();
        assert_eq!(custom.endpoint(), "https://custom.example.test");
        assert!(
            custom.cfg.giver_secret.is_none(),
            "generic connect must not carry shellnet test funding secrets"
        );

        let shellnet = ChainClient::shellnet().unwrap();
        assert!(
            shellnet.cfg.giver_secret.is_some(),
            "shellnet preset still carries shellnet config"
        );
    }

    #[test]
    fn value_as_u32_rejects_non_integer_currency_ids() {
        assert_eq!(value_as_u32(&serde_json::json!(2)).unwrap(), 2);
        assert_eq!(value_as_u32(&serde_json::json!(2.0)).unwrap(), 2);
        assert!(value_as_u32(&serde_json::json!(2.5)).is_err());
        assert!(value_as_u32(&serde_json::json!(-1)).is_err());
    }

    #[test]
    fn account_balance_helpers() {
        let acc = Account {
            address: Address::parse(&"1".repeat(64)).unwrap(),
            status: "Active".to_string(),
            balance: 1000,
            ecc: vec![(1, 42), (2, 777)],
            code_hash: None,
            boc: None,
        };
        assert!(acc.is_active());
        assert_eq!(acc.shell(), 777);
        assert_eq!(acc.ecc_balance(1), 42);
        assert_eq!(acc.ecc_balance(99), 0);
    }

    /// Live read against shellnet: the system Giver (`0:1111…`) must come back
    /// Active with a non-zero native balance and SHELL. Plus a liveness probe.
    /// Run: `cargo test --lib sdk::client::tests::live -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn live_get_account_and_liveness() {
        let client = ChainClient::shellnet().unwrap();

        let live = client.chain_liveness().await.expect("liveness");
        eprintln!(
            "liveness: block #{} {}s old → {}",
            live.latest_seq_no,
            live.latest_block_age_secs,
            if live.is_live() { "LIVE" } else { "HALTED" }
        );

        let giver = Address::parse(&"1".repeat(64)).unwrap();
        let acc = client
            .get_account(&giver)
            .await
            .expect("get_account")
            .expect("giver exists");
        eprintln!(
            "giver: status={} native={} shell={} ecc={:?}",
            acc.status,
            acc.balance,
            acc.shell(),
            acc.ecc
        );
        assert!(acc.is_active(), "giver must be Active");
        assert!(acc.balance > 0, "giver must hold native VMSHELL");
    }
}
