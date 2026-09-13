// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Read-path transport: fetch an account's BOC from the shellnet GraphQL API.
//!
//! Acki Nacki's GraphQL `blockchain.account(account_id, dapp_id)` is
//! **DApp-aware** and takes **bare 64-hex** ids (no `0:` prefix). It returns
//! `boc` / `code_hash` / `acc_type_name` etc. Getters are then run **locally**
//! against the fetched `boc` (next increment, via `tvm_client::run_tvm`) — we
//! never poll getters in a loop; live state changes are tracked via events.
//!
//! `dapp_id` rule (see `AiRegistryConfig`): a per-call value wins, else the
//! config override, else the default — `dapp_id == account_id` for
//! self-originating airegistry contracts. The default is confirmed empirically
//! on the first live deploy (Phase 2).

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::config::AiRegistryConfig;

/// Minimal account snapshot read from GraphQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSnapshot {
    /// Bare 64-hex account id (no `0:`).
    pub account_id: String,
    /// `Uninit` | `Active` | `Frozen` | `NonExist` (GraphQL `acc_type_name`).
    pub acc_type_name: String,
    /// Account BOC (base64), present when the account exists.
    pub boc: Option<String>,
    /// Code hash (hex), present when the account has code.
    pub code_hash: Option<String>,
}

impl AccountSnapshot {
    pub fn is_active(&self) -> bool {
        self.acc_type_name == "Active"
    }
}

/// A liveness snapshot of the chain as seen through the Block Manager: the
/// newest block's `seq_no` and how long ago it was produced, measured against
/// the BM's *own* clock (so client clock skew is irrelevant).
///
/// Acki Nacki produces blocks every few seconds when healthy, so a
/// `latest_block_age_secs` past a small threshold means block production has
/// stalled — the chain is halted. A halt is treacherous: the BM keeps serving
/// reads (getters/GraphQL stay green) while `/v2/messages` starts rejecting
/// every write with `QUEUE_OVERFLOW` (queues fill with nothing draining them).
/// This snapshot lets a caller tell "my message was malformed" apart from "the
/// network is down".
#[derive(Debug, Clone)]
pub struct ChainLiveness {
    /// `seq_no` of the newest block the BM reports.
    pub latest_seq_no: u64,
    /// Age of that block in seconds (BM clock − block `gen_utime`); minor clock
    /// skew is clamped to 0.
    pub latest_block_age_secs: i64,
    /// The staleness threshold this snapshot was taken with.
    pub stale_after_secs: i64,
}

impl ChainLiveness {
    /// True when the newest block is within the staleness threshold — i.e. the
    /// chain is still producing blocks and writes can land.
    pub fn is_live(&self) -> bool {
        self.latest_block_age_secs <= self.stale_after_secs
    }
}

/// Strip a leading `0:` (or `-1:`) workchain prefix, returning bare lowercase
/// 64-hex. Errors if the result is not exactly 64 hex chars.
pub fn bare_account_id(addr: &str) -> Result<String> {
    let hex = addr
        .rsplit(':')
        .next()
        .unwrap_or(addr)
        .trim()
        .to_lowercase();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "account id must be 64 hex chars (optionally '0:'-prefixed), got {addr:?}"
        ));
    }
    Ok(hex)
}

/// Declares **how an account got its DApp id**, so the read path can never
/// silently default a SwarmRoot-child wallet to its own account id.
///
/// The spec's dapp_id rule has two cases, and the caller must say which:
/// - self-originating airegistry contracts (SuperRoot/RootModel/Token/Manifest)
///   ⇒ `dapp_id == account_id`;
/// - SwarmRoot-child wallets (treasury/operational `SwarmMultisigWallet`) ⇒ they
///   inherit the SwarmRoot's DApp id, which must be passed explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOrigin {
    /// Deployed by external message; DApp id = own account id.
    SelfOriginating,
    /// Deployed inside a SwarmRoot DApp; DApp id = the SwarmRoot's DApp id.
    SwarmChild { dapp_id: String },
    /// Force a specific DApp id (escape hatch / per-call override).
    Explicit { dapp_id: String },
}

/// Resolve the dapp_id to query for `account_id`.
///
/// Precedence (per spec §4 — `dapp_id_override` is "always overridable per
/// call"): a **per-call** dapp_id wins, then the network-wide config override,
/// then the origin default. Concretely:
///   1. `Explicit { dapp_id }` / `SwarmChild { dapp_id }` — a dapp_id passed for
///      this call always wins (lets one request read another SuperRoot/instance
///      or a child wallet's real DApp id, regardless of any config override);
///   2. `cfg.dapp_id_override` — overrides the *default* network-wide;
///   3. default — `account_id` for a self-originating account.
///
/// There is **no** blanket "default to account id" for child wallets: a
/// `SwarmChild` read must carry its dapp_id, so an operational wallet can't be
/// queried under the wrong DApp.
pub fn resolve_dapp_id(
    account_id_bare: &str,
    cfg: &AiRegistryConfig,
    origin: &AccountOrigin,
) -> Result<String> {
    match origin {
        // Per-call dapp_id wins over the config override (escape hatch preserved).
        AccountOrigin::SwarmChild { dapp_id } | AccountOrigin::Explicit { dapp_id } => {
            bare_account_id(dapp_id)
        }
        // Self-originating: config override of the default, else account_id.
        AccountOrigin::SelfOriginating => match cfg.dapp_id_override.as_deref() {
            Some(over) => bare_account_id(over),
            None => bare_account_id(account_id_bare),
        },
    }
}

/// Build the GraphQL query body for one account.
pub fn account_query(account_id_bare: &str, dapp_id_bare: &str) -> Value {
    let q = format!(
        "{{ blockchain {{ account(account_id: \"{account_id_bare}\", \
         dapp_id: \"{dapp_id_bare}\") {{ info {{ \
         address acc_type_name boc code_hash }} }} }} }}"
    );
    serde_json::json!({ "query": q })
}

/// GraphQL query for a forward page of the account's messages (oldest-first
/// Relay connection): `first` per page, resuming `after` a cursor. `msg_type ==
/// 2` is an ext-out message — an emitted **event** — whose `body` decodes to an
/// [`AiRegistryEvent`]. Each node carries stable identity (`id`, `created_lt` =
/// canonical on-chain order) and a pagination `cursor`; `pageInfo` lets a
/// backend indexer checkpoint and know when it has caught up. This is the
/// event-log read path, distinct from the getter-over-BOC state read.
pub fn messages_query(
    account_id_bare: &str,
    dapp_id_bare: &str,
    first: u32,
    after: Option<&str>,
) -> Value {
    let after_clause = match after {
        Some(c) if !c.is_empty() => format!(", after: \"{c}\""),
        _ => String::new(),
    };
    let q = format!(
        "{{ blockchain {{ account(account_id: \"{account_id_bare}\", \
         dapp_id: \"{dapp_id_bare}\") {{ messages(first: {first}{after_clause}) {{ \
         edges {{ cursor node {{ id msg_type body created_lt created_at }} }} \
         pageInfo {{ hasNextPage endCursor }} }} }} }} }}"
    );
    serde_json::json!({ "query": q })
}

/// Parse a GraphQL `blockchain.account.messages` connection into an [`EventPage`],
/// **failing closed**: a null/absent account, a missing messages connection, or
/// a missing `edges`/`pageInfo` is an error — never a success-shaped empty page
/// (a downstream indexer must not checkpoint "not found" as "caught up").
/// `address` is used only for the error message; `contract` decodes ext-out
/// event bodies. (Production code goes through [`AccountReader::read_events`] /
/// [`parse_messages_page_with`]; this airegistry-typed wrapper remains as the
/// seam the fail-closed tests pin down.)
#[cfg(test)]
fn parse_messages_page(
    resp: &Value,
    address: &str,
    contract: &tvm_abi::Contract,
) -> Result<EventPage> {
    parse_messages_page_with(resp, address, &|body_b64| {
        crate::airegistry::events::decode_event_body_b64(contract, body_b64).ok()
    })
}

/// Generic twin of [`parse_messages_page`]: same fail-closed page semantics, but
/// ext-out bodies are decoded by the caller's `decode` (base64 body → typed
/// event; `None` skips the message as foreign/undecodable while still counting
/// it in `scanned` and advancing the cursor). This is what non-airegistry event
/// families (e.g. [`crate::inference`]) plug their decoders into.
pub fn parse_messages_page_with<E>(
    resp: &Value,
    address: &str,
    decode: &(dyn Fn(&str) -> Option<E> + Sync),
) -> Result<EventPage<E>> {
    match resp.pointer("/data/blockchain/account") {
        Some(a) if !a.is_null() => {}
        _ => {
            return Err(anyhow!(
                "account not found or not readable for {address} (check the address / dapp_id)"
            ))
        }
    }
    let conn = resp
        .pointer("/data/blockchain/account/messages")
        .filter(|c| c.is_object())
        .ok_or_else(|| {
            anyhow!("account.messages connection missing — the account exists but the message log was not returned")
        })?;
    let edges = conn
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("account.messages.edges missing or not an array"))?;
    let scanned = edges.len();
    let mut records = Vec::new();
    for e in edges {
        let node = e.get("node");
        if node
            .and_then(|n| n.get("msg_type"))
            .and_then(|v| v.as_i64())
            != Some(2)
        {
            continue;
        }
        let Some(b) = node.and_then(|n| n.get("body")).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(event) = decode(b) else {
            continue;
        };
        records.push(EventRecord {
            event,
            message_id: node
                .and_then(|n| n.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            created_lt: node
                .and_then(|n| n.get("created_lt"))
                .and_then(|v| v.as_str())
                .map(String::from),
            created_at: node
                .and_then(|n| n.get("created_at"))
                .and_then(|v| v.as_i64()),
            cursor: e
                .get("cursor")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        });
    }
    let page_info = conn
        .get("pageInfo")
        .filter(|p| p.is_object())
        .ok_or_else(|| anyhow!("account.messages.pageInfo missing"))?;
    let has_more = page_info
        .get("hasNextPage")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let end_cursor = page_info
        .get("endCursor")
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(EventPage {
        records,
        scanned,
        has_more,
        end_cursor,
    })
}

/// One decoded event with its on-chain identity and pagination cursor. Generic
/// over the decoded event type; defaults to the airegistry event family so
/// existing callers are unchanged.
#[derive(Debug, Clone)]
pub struct EventRecord<E = crate::airegistry::events::AiRegistryEvent> {
    pub event: E,
    /// Stable on-chain message id.
    pub message_id: String,
    /// Logical time (hex) — the canonical on-chain ordering key.
    pub created_lt: Option<String>,
    pub created_at: Option<i64>,
    /// Opaque pagination cursor for this message (resume `after` it).
    pub cursor: String,
}

/// A forward page of events with the sync metadata a backend indexer needs to
/// checkpoint and detect catch-up.
#[derive(Debug, Clone)]
pub struct EventPage<E = crate::airegistry::events::AiRegistryEvent> {
    pub records: Vec<EventRecord<E>>,
    /// Messages scanned this page (events + non-events) — a progress signal.
    pub scanned: usize,
    /// More messages exist after `end_cursor`.
    pub has_more: bool,
    /// Resume point: pass as `after` to continue; persist as a checkpoint.
    pub end_cursor: Option<String>,
}

/// Parse a GraphQL account response into an `AccountSnapshot`.
/// Returns `Ok(None)` when the account node is null (not found / never seen).
pub fn parse_account_response(resp: &Value) -> Result<Option<AccountSnapshot>> {
    if let Some(errors) = resp.get("errors") {
        if !errors.is_null() {
            return Err(anyhow!("GraphQL errors: {errors}"));
        }
    }
    let info = resp.pointer("/data/blockchain/account/info");
    let info = match info {
        Some(v) if !v.is_null() => v,
        _ => return Ok(None),
    };
    let account_id = info
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("account info missing address"))?
        .to_string();
    let acc_type_name = info
        .get("acc_type_name")
        .and_then(|v| v.as_str())
        .unwrap_or("NonExist")
        .to_string();
    let boc = info.get("boc").and_then(|v| v.as_str()).map(str::to_string);
    let code_hash = info
        .get("code_hash")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Ok(Some(AccountSnapshot {
        account_id,
        acc_type_name,
        boc,
        code_hash,
    }))
}

/// GraphQL read client for account BOCs.
#[derive(Clone)]
pub struct AccountReader {
    http: reqwest::Client,
    graphql_url: String,
}

impl AccountReader {
    /// `send_endpoint` is the network's HTTP endpoint (e.g.
    /// `https://shellnet.ackinacki.org`); the GraphQL path is appended.
    pub fn new(http: reqwest::Client, send_endpoint: &str) -> Self {
        Self {
            http,
            graphql_url: format!("{}/graphql", send_endpoint.trim_end_matches('/')),
        }
    }

    pub fn graphql_url(&self) -> &str {
        &self.graphql_url
    }

    /// Fetch an account snapshot. The caller MUST declare the account
    /// [`AccountOrigin`] so a SwarmRoot-child wallet is never silently queried
    /// under its own account id. `Ok(None)` ⇒ account not found.
    pub async fn fetch(
        &self,
        cfg: &AiRegistryConfig,
        address: &str,
        origin: &AccountOrigin,
    ) -> Result<Option<AccountSnapshot>> {
        let account_id = bare_account_id(address)?;
        let dapp_id = resolve_dapp_id(&account_id, cfg, origin)?;
        let body = account_query(&account_id, &dapp_id);
        let resp: Value = self
            .http
            .post(&self.graphql_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.graphql_url))?
            .error_for_status()?
            .json()
            .await
            .context("parse GraphQL account response")?;
        parse_account_response(&resp)
    }

    /// Convenience: fetch a **self-originating** airegistry contract account
    /// (SuperRoot/RootModel/Token/Manifest), where dapp_id == account_id.
    pub async fn fetch_self_originating(
        &self,
        cfg: &AiRegistryConfig,
        address: &str,
    ) -> Result<Option<AccountSnapshot>> {
        self.fetch(cfg, address, &AccountOrigin::SelfOriginating)
            .await
    }

    /// Read a forward page of the account's emitted **events** (ext-out /
    /// `msg_type == 2` messages), decoded against `abi_json`. This is the
    /// event-log read — the blockchain-native way to discover registrations and
    /// track activity, with no BOC download / local getter execution. `first`
    /// bounds the page; `after` resumes from a prior cursor (checkpoint). Each
    /// record carries stable identity (`message_id`, `created_lt`) + a cursor,
    /// and the page reports `has_more` / `end_cursor` so a backend indexer can
    /// sync incrementally and know when it has caught up. Foreign/undecodable
    /// messages are skipped (but still counted in `scanned` and advance the
    /// cursor). The caller declares the [`AccountOrigin`] (DApp id).
    pub async fn read_events(
        &self,
        cfg: &AiRegistryConfig,
        address: &str,
        abi_json: &str,
        origin: &AccountOrigin,
        first: u32,
        after: Option<&str>,
    ) -> Result<EventPage> {
        let contract = tvm_abi::Contract::load(abi_json.as_bytes())
            .map_err(|e| anyhow!("load event ABI: {e}"))?;
        self.read_events_with(cfg, address, origin, first, after, &|body_b64| {
            crate::airegistry::events::decode_event_body_b64(&contract, body_b64).ok()
        })
        .await
    }

    /// Generic twin of [`AccountReader::read_events`]: the same fail-closed
    /// paged event-log read, decoding each ext-out body with the caller's
    /// `decode` (`None` skips the message as foreign). Lets other event families
    /// (e.g. the inference market, [`crate::inference::events`]) reuse the sync
    /// contract — stable ids, cursors, `has_more` — with their own typed events.
    pub async fn read_events_with<E>(
        &self,
        cfg: &AiRegistryConfig,
        address: &str,
        origin: &AccountOrigin,
        first: u32,
        after: Option<&str>,
        decode: &(dyn Fn(&str) -> Option<E> + Sync),
    ) -> Result<EventPage<E>> {
        let account_id = bare_account_id(address)?;
        let dapp_id = resolve_dapp_id(&account_id, cfg, origin)?;
        let body = messages_query(&account_id, &dapp_id, first, after);
        let resp: Value = self
            .http
            .post(&self.graphql_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.graphql_url))?
            .error_for_status()?
            .json()
            .await
            .context("parse GraphQL messages response")?;
        if let Some(errors) = resp.get("errors") {
            if !errors.is_null() {
                return Err(anyhow!("GraphQL errors: {errors}"));
            }
        }
        parse_messages_page_with(&resp, address, decode)
    }

    /// Probe chain liveness: read the newest block and compare its production
    /// time to the Block Manager's current clock. `stale_after_secs` is the
    /// threshold beyond which the chain is judged halted (60s sits well clear of
    /// the normal few-second block cadence). Both facts come from one GraphQL
    /// round-trip. Errors only if the BM is unreachable or reports no blocks — a
    /// *halted* chain is a successful `Ok` with `is_live() == false`, not an error.
    pub async fn chain_liveness(&self, stale_after_secs: i64) -> Result<ChainLiveness> {
        let body = serde_json::json!({
            "query": "{ info { time } blockchain { blocks(last:1){ edges { node { seq_no gen_utime } } } } }"
        });
        let resp: Value = self
            .http
            .post(&self.graphql_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.graphql_url))?
            .error_for_status()?
            .json()
            .await
            .context("parse GraphQL liveness response")?;
        if let Some(errors) = resp.get("errors") {
            if !errors.is_null() {
                return Err(anyhow!("GraphQL errors: {errors}"));
            }
        }
        // The BM serves `info.time` in milliseconds; block `gen_utime` is Unix
        // seconds. Use the BM clock as "now" so the age is skew-free.
        let now_secs = resp
            .pointer("/data/info/time")
            .and_then(|v| v.as_f64())
            .map(|ms| (ms / 1000.0) as i64)
            .ok_or_else(|| anyhow!("liveness: missing info.time"))?;
        let node = resp
            .pointer("/data/blockchain/blocks/edges/0/node")
            .ok_or_else(|| anyhow!("liveness: BM reported no blocks"))?;
        let latest_seq_no = node
            .get("seq_no")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("liveness: block missing seq_no"))?;
        let gen_utime = node
            .get("gen_utime")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("liveness: block missing gen_utime"))?;
        let latest_block_age_secs = (now_secs - gen_utime).max(0);
        Ok(ChainLiveness {
            latest_seq_no,
            latest_block_age_secs,
            stale_after_secs,
        })
    }

    /// True if the account is `Active`. `false` for Uninit/NonExist/not found.
    pub async fn is_active(
        &self,
        cfg: &AiRegistryConfig,
        address: &str,
        origin: &AccountOrigin,
    ) -> Result<bool> {
        Ok(self
            .fetch(cfg, address, origin)
            .await?
            .map(|s| s.is_active())
            .unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_liveness_is_live_threshold() {
        let live = ChainLiveness {
            latest_seq_no: 100,
            latest_block_age_secs: 5,
            stale_after_secs: 60,
        };
        assert!(live.is_live(), "a 5s-old tip is live");
        let halted = ChainLiveness {
            latest_seq_no: 1025183,
            latest_block_age_secs: 22340,
            stale_after_secs: 60,
        };
        assert!(!halted.is_live(), "a 6h-old tip is halted");
        let edge = ChainLiveness {
            latest_seq_no: 1,
            latest_block_age_secs: 60,
            stale_after_secs: 60,
        };
        assert!(edge.is_live(), "exactly at the threshold is still live");
    }

    fn dummy_event_contract() -> tvm_abi::Contract {
        tvm_abi::Contract::load(
            crate::airegistry::abi::Contract::SuperRoot
                .abi_json()
                .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn parse_messages_page_account_null_or_missing_fails_closed() {
        let c = dummy_event_contract();
        // account explicitly null
        let null_acc = serde_json::json!({ "data": { "blockchain": { "account": null } } });
        assert!(parse_messages_page(&null_acc, "0:abc", &c)
            .unwrap_err()
            .to_string()
            .contains("not found"));
        // account node absent
        let no_acc = serde_json::json!({ "data": { "blockchain": {} } });
        assert!(parse_messages_page(&no_acc, "0:abc", &c).is_err());
    }

    #[test]
    fn parse_messages_page_messages_missing_fails_closed() {
        let c = dummy_event_contract();
        let resp = serde_json::json!({ "data": { "blockchain": { "account": { "info": {} } } } });
        let err = parse_messages_page(&resp, "0:abc", &c)
            .unwrap_err()
            .to_string();
        assert!(err.contains("messages connection missing"), "got: {err}");
    }

    #[test]
    fn parse_messages_page_empty_but_present_is_valid_empty_page() {
        let c = dummy_event_contract();
        let resp = serde_json::json!({ "data": { "blockchain": { "account": {
            "messages": { "edges": [], "pageInfo": { "hasNextPage": false, "endCursor": null } }
        } } } });
        let page = parse_messages_page(&resp, "0:abc", &c).expect("empty-but-present log is valid");
        assert_eq!(page.scanned, 0);
        assert!(page.records.is_empty());
        assert!(!page.has_more);
        assert!(page.end_cursor.is_none());
    }

    #[test]
    fn bare_account_id_strips_prefix() {
        let hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert_eq!(bare_account_id(&format!("0:{hex}")).unwrap(), hex);
        assert_eq!(bare_account_id(&format!("-1:{hex}")).unwrap(), hex);
        assert_eq!(bare_account_id(hex).unwrap(), hex);
        assert_eq!(
            bare_account_id(&format!("0:{}", hex.to_uppercase())).unwrap(),
            hex
        );
    }

    #[test]
    fn bare_account_id_rejects_bad() {
        assert!(bare_account_id("0:tooshort").is_err());
        assert!(bare_account_id("").is_err());
        assert!(bare_account_id(
            "0:zz34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        .is_err());
    }

    const ACC: &str = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const SR: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn self_originating_dapp_id_is_account_id() {
        let cfg = AiRegistryConfig::shellnet();
        assert_eq!(
            resolve_dapp_id(ACC, &cfg, &AccountOrigin::SelfOriginating).unwrap(),
            ACC
        );
    }

    #[test]
    fn swarm_child_uses_swarmroot_dapp_id_not_account_id() {
        // Regression: a SwarmRoot-child wallet MUST query under the SwarmRoot
        // DApp id, never its own account id. There is no API path that defaults
        // a SwarmChild to account_id — the origin requires an explicit dapp_id.
        let cfg = AiRegistryConfig::shellnet();
        let got = resolve_dapp_id(
            ACC,
            &cfg,
            &AccountOrigin::SwarmChild {
                dapp_id: format!("0:{SR}"),
            },
        )
        .unwrap();
        assert_eq!(got, SR);
        assert_ne!(
            got, ACC,
            "child wallet must not default to its own account id"
        );
    }

    #[test]
    fn explicit_origin_forces_dapp_id() {
        let cfg = AiRegistryConfig::shellnet();
        assert_eq!(
            resolve_dapp_id(
                ACC,
                &cfg,
                &AccountOrigin::Explicit {
                    dapp_id: format!("0:{SR}")
                }
            )
            .unwrap(),
            SR
        );
    }

    #[test]
    fn config_override_changes_self_originating_default() {
        // The override replaces the account_id default for self-originating reads.
        let mut cfg = AiRegistryConfig::shellnet();
        cfg.dapp_id_override = Some(format!("0:{SR}"));
        assert_eq!(
            resolve_dapp_id(ACC, &cfg, &AccountOrigin::SelfOriginating).unwrap(),
            SR
        );
    }

    #[test]
    fn per_call_dapp_id_wins_over_config_override() {
        // Regression: spec §4 — dapp_id_override is "always overridable per
        // call". A per-call Explicit/SwarmChild dapp_id must win over the
        // network-wide override, so one request can read another instance.
        let third = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let mut cfg = AiRegistryConfig::shellnet();
        cfg.dapp_id_override = Some(format!("0:{SR}"));
        assert_eq!(
            resolve_dapp_id(
                ACC,
                &cfg,
                &AccountOrigin::Explicit {
                    dapp_id: format!("0:{third}")
                }
            )
            .unwrap(),
            third,
            "per-call Explicit must override config dapp_id_override"
        );
        assert_eq!(
            resolve_dapp_id(
                ACC,
                &cfg,
                &AccountOrigin::SwarmChild {
                    dapp_id: format!("0:{third}")
                }
            )
            .unwrap(),
            third,
            "per-call SwarmChild dapp_id must override config dapp_id_override"
        );
    }

    #[test]
    fn account_query_uses_bare_hex_no_prefix() {
        let acc = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let q = account_query(acc, acc);
        let s = q["query"].as_str().unwrap();
        assert!(s.contains(&format!("account_id: \"{acc}\"")));
        assert!(s.contains(&format!("dapp_id: \"{acc}\"")));
        assert!(!s.contains("0:"), "query must not carry a 0: prefix");
        assert!(s.contains("acc_type_name") && s.contains("boc") && s.contains("code_hash"));
    }

    #[test]
    fn parse_active_account() {
        let resp = serde_json::json!({
            "data": { "blockchain": { "account": { "info": {
                "address": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "acc_type_name": "Active",
                "boc": "te6ccg...",
                "code_hash": "efad28990e37eea28b720eec990b255d498e265ef1b7a1440111c4cef37118a5"
            }}}}
        });
        let snap = parse_account_response(&resp).unwrap().unwrap();
        assert!(snap.is_active());
        assert_eq!(snap.boc.as_deref(), Some("te6ccg..."));
        assert!(snap.code_hash.is_some());
    }

    #[test]
    fn parse_null_account_is_none() {
        let resp = serde_json::json!({"data": {"blockchain": {"account": null}}});
        assert!(parse_account_response(&resp).unwrap().is_none());
    }

    #[test]
    fn parse_uninit_account() {
        let resp = serde_json::json!({
            "data": { "blockchain": { "account": { "info": {
                "address": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "acc_type_name": "Uninit", "boc": null, "code_hash": null
            }}}}
        });
        let snap = parse_account_response(&resp).unwrap().unwrap();
        assert!(!snap.is_active());
        assert!(snap.boc.is_none());
    }

    #[test]
    fn parse_graphql_errors_bubble_up() {
        let resp = serde_json::json!({"errors": [{"message": "bad dapp_id"}], "data": null});
        assert!(parse_account_response(&resp).is_err());
    }

    #[test]
    fn reader_builds_graphql_url() {
        let r = AccountReader::new(reqwest::Client::new(), "https://shellnet.ackinacki.org/");
        assert_eq!(r.graphql_url(), "https://shellnet.ackinacki.org/graphql");
    }

    /// Live end-to-end fetch against shellnet (env-gated). Reads the Giver at
    /// `0:1111…` (a known Active account) and asserts the boc/code_hash come
    /// back. Run: `GOSH_AIREGISTRY_LIVE=1 cargo test --lib airegistry::getter::tests::live`.
    #[tokio::test]
    async fn live_fetch_giver() {
        if std::env::var("GOSH_AIREGISTRY_LIVE").is_err() {
            eprintln!("live_fetch_giver: SKIPPED (set GOSH_AIREGISTRY_LIVE=1)");
            return;
        }
        let cfg = AiRegistryConfig::shellnet();
        let reader = AccountReader::new(reqwest::Client::new(), "https://shellnet.ackinacki.org");
        let giver = cfg.giver_address.clone().unwrap();
        let snap = reader
            .fetch_self_originating(&cfg, &giver)
            .await
            .expect("fetch")
            .expect("giver account exists");
        eprintln!(
            "LIVE giver: acc_type={} boc_len={:?} code_hash={:?}",
            snap.acc_type_name,
            snap.boc.as_ref().map(|b| b.len()),
            snap.code_hash
        );
        assert!(snap.is_active(), "giver should be Active");
        assert!(snap.boc.is_some(), "giver should return a boc");
        assert!(snap.code_hash.is_some());
    }
}
