// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! MCP tool handlers for gosh-ackinacki.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::filter::rules::{FilterRule, MsgTypeFilter};
use crate::state::{AppState, ServeMode};
use crate::wallet;

pub(crate) const WALLET_PRIVKEY_KIND: &str = "ackinacki.wallet.privkey";
pub(crate) const WALLET_PUBKEY_KIND: &str = "ackinacki.wallet.pubkey";
pub(crate) const WALLET_METADATA_KIND: &str = "ackinacki.wallet.metadata";

/// In-memory per-wallet rate limiter for transaction endpoints.
/// Limits to `MAX_CALLS` calls per `WINDOW` per wallet address.
pub struct TxRateLimiter {
    /// wallet_address -> (window_start, call_count)
    buckets: parking_lot::Mutex<HashMap<String, (Instant, u32)>>,
}

const TX_RATE_LIMIT_MAX_CALLS: u32 = 10;
const TX_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

impl TxRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Check and consume one call for the given wallet. Returns Err if rate limit exceeded.
    pub fn check(&self, wallet_address: &str) -> Result<()> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock();

        // Evict expired entries to prevent unbounded growth
        buckets.retain(|_, (start, _)| now.duration_since(*start) < TX_RATE_LIMIT_WINDOW * 2);

        let entry = buckets
            .entry(wallet_address.to_string())
            .or_insert((now, 0));

        if now.duration_since(entry.0) >= TX_RATE_LIMIT_WINDOW {
            *entry = (now, 1);
            Ok(())
        } else if entry.1 < TX_RATE_LIMIT_MAX_CALLS {
            entry.1 += 1;
            Ok(())
        } else {
            bail!(
                "rate limit exceeded for wallet {wallet_address}: max {TX_RATE_LIMIT_MAX_CALLS} transaction calls per minute"
            )
        }
    }
}

impl Default for TxRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRateLimiter {
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

/// Tools served in AI Registry **read-only** mode — pure chain-first reads with
/// no gosh.memory and no local-state mutation. Everything else (wallets, secrets,
/// policies, deploys/writes, subscriptions, ABI registration, fact ingest) needs
/// the full Memory-backed agent. `tools/list` advertises only this subset in
/// read-only mode, and [`call_tool`] rejects anything outside it — so `tools/list`
/// is an honest capability contract for an integrator.
pub fn is_read_only_safe(name: &str) -> bool {
    matches!(
        name,
        "call_contract"
            | "airegistry_resolve_model"
            | "airegistry_get_manifest"
            | "airegistry_get_lot"
            | "airegistry_get_entitlement"
            | "airegistry_list_marketplace"
            // pure read (no keys) — readiness verification belongs in read-only too.
            | "airegistry_verify_payment_readiness"
    )
}

/// Stateless-payments PREPARE tools (Flow A): build a payment payload the user's
/// own wallet signs. No gosh.memory, no key material. (Readiness verification is
/// a pure read and lives in [`is_read_only_safe`].)
pub fn is_stateless_payment_tool(name: &str) -> bool {
    matches!(
        name,
        "airegistry_prepare_user_buy_tokens" | "airegistry_prepare_user_cancel"
    )
}

/// Whether `name` is served in `mode` — the capability contract `tools/list`
/// advertises and [`call_tool`] enforces.
pub fn tool_served(mode: ServeMode, name: &str) -> bool {
    match mode {
        ServeMode::Full => true,
        ServeMode::ReadOnly => is_read_only_safe(name),
        ServeMode::StatelessPayments => is_read_only_safe(name) || is_stateless_payment_tool(name),
    }
}

/// Return the available MCP tools for `mode` — only the served subset
/// ([`tool_served`]) is advertised, so `tools/list` is an honest contract.
pub fn list_tools(mode: ServeMode) -> Vec<Value> {
    let mut tools = vec![
        json!({
            "name": "subscribe_address",
            "description": "Subscribe to blockchain messages from/to an address",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Account address (workchain:hex)" },
                    "msg_types": {
                        "type": "array",
                        "items": { "type": "string", "enum": ["internal", "ext_in", "ext_out"] },
                        "description": "Message types to match (default: all)"
                    },
                    "methods": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "ABI method names to match (default: all)"
                    }
                },
                "required": ["address"]
            }
        }),
        json!({
            "name": "unsubscribe_address",
            "description": "Remove an address from the subscription filter",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string" }
                },
                "required": ["address"]
            }
        }),
        json!({
            "name": "list_subscriptions",
            "description": "List current filter rules",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "register_abi",
            "description": "Register contract ABI for message decoding",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Contract address" },
                    "abi_json": { "type": "string", "description": "ABI JSON string" }
                },
                "required": ["address", "abi_json"]
            }
        }),
        json!({
            "name": "create_keys",
            "description": "Generate Ed25519 keypair for wallet custodian; persisted in gosh.memory via memory_object_upsert.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": ["agent", "controller", "owner"],
                        "description": "Custodian role"
                    },
                    "wallet_id": { "type": "string", "description": "Wallet identifier" }
                },
                "required": ["role", "wallet_id"]
            }
        }),
        json!({
            "name": "get_wallet_status",
            "description": "Check if all 3 custodian keys are present for a wallet",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_id": { "type": "string" }
                },
                "required": ["wallet_id"]
            }
        }),
        json!({
            "name": "set_wallet_policy",
            "description": "Set spending policy for a wallet",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_address": { "type": "string" },
                    "max_tx_amount": { "type": "number" },
                    "allowed_destinations": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "policy_tier": {
                        "type": "string",
                        "enum": ["standard", "premium", "restricted", "frozen"]
                    }
                },
                "required": ["wallet_address"]
            }
        }),
        json!({
            "name": "get_wallet_policy",
            "description": "Get spending policy for a wallet",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_address": { "type": "string" }
                },
                "required": ["wallet_address"]
            }
        }),
        json!({
            "name": "deploy_wallet",
            "description": "Deploy a 2-of-3 multisig wallet via SwarmRoot (inherits DApp ID for gasless txs). Requires the SwarmRoot owner private key to be pre-seeded as a namespace secret in gosh.memory under name 'swarm_root:<addr>:owner:privkey' (via memory_namespace_secret_set by namespace admin).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_id": { "type": "string", "description": "Wallet identifier (must have agent/controller/owner keys created)" },
                    "swarm_root_address": { "type": "string", "description": "SwarmRoot contract address. Its owner key must be pre-seeded as a namespace secret." }
                },
                "required": ["wallet_id", "swarm_root_address"]
            }
        }),
        json!({
            "name": "send_transaction",
            "description": "Submit a transaction from multisig wallet (requires 2nd confirmation)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_address": { "type": "string" },
                    "dest": { "type": "string", "description": "Destination address" },
                    "value": { "type": "string", "description": "Amount in nanotoken" },
                    "bounce": { "type": "boolean", "description": "Bounce if dest doesn't exist" },
                    "signer_role": { "type": "string", "enum": ["agent", "controller", "owner"] },
                    "wallet_id": { "type": "string" }
                },
                "required": ["wallet_address", "dest", "value", "signer_role", "wallet_id"]
            }
        }),
        json!({
            "name": "confirm_transaction",
            "description": "Confirm a pending multisig transaction",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wallet_address": { "type": "string" },
                    "transaction_id": { "type": "integer" },
                    "signer_role": { "type": "string", "enum": ["agent", "controller", "owner"] },
                    "wallet_id": { "type": "string" },
                    "dapp_id": { "type": "string", "description": "The wallet's DApp id for reading the queued transaction (its SwarmRoot address for a SwarmRoot-child wallet; its own address if self-originating). Needed to policy-check the queued dest/amount before releasing the second signature." }
                },
                "required": ["wallet_address", "transaction_id", "signer_role", "wallet_id"]
            }
        }),
    ];
    tools.extend(super::airegistry::list_airegistry_tools());
    if mode != ServeMode::Full {
        tools.retain(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(|n| tool_served(mode, n))
                .unwrap_or(false)
        });
        // `call_contract` is getter-only in a no-Memory mode: drop the signed-write
        // (`signer_ref`) path from the advertised schema so `tools/list` is honest.
        for t in tools.iter_mut() {
            if t.get("name").and_then(|n| n.as_str()) == Some("call_contract") {
                t["description"] = json!(
                    "Run an ABI getter (read) on a contract. Use `contract` \
                     (SuperRoot|RootModel|TokenContract|ManifestMetadata) or raw \
                     `abi_json`. No-Memory mode: getter reads only — signed writes \
                     (signer_ref) are not available."
                );
                if let Some(props) = t
                    .pointer_mut("/inputSchema/properties")
                    .and_then(|p| p.as_object_mut())
                {
                    props.remove("signer_ref");
                }
            }
        }
    }
    tools
}

/// Dispatch a tool call.
pub async fn call_tool(state: &AppState, name: &str, args: Value) -> Result<Value> {
    // A no-Memory mode serves only its subset; everything else is rejected up
    // front so `tools/list` stays an honest capability contract.
    if !tool_served(state.mode(), name) {
        bail!(
            "tool '{name}' is not available in this mode \
             (this service runs without gosh.memory); restart without --read-only / \
             --stateless-payments (with gosh.memory) for the full Memory-backed agent"
        );
    }
    // `call_contract` is getter-only in a no-Memory mode: the signed-write path
    // (`signer_ref`) needs Memory-backed signer resolution and is not advertised,
    // so reject it explicitly instead of failing deep in signer resolution.
    if state.is_read_only() && name == "call_contract" && args.get("signer_ref").is_some() {
        bail!(
            "signed write via call_contract (signer_ref) is not available in a \
             no-Memory mode (getter reads only); restart without --read-only / \
             --stateless-payments (with gosh.memory) for the full Memory-backed agent"
        );
    }
    // airegistry (SPC token) tools handle their own names; fall through otherwise.
    if let Some(result) = super::airegistry::call_airegistry_tool(state, name, args.clone()).await {
        return result;
    }
    match name {
        "subscribe_address" => subscribe_address(state, args),
        "unsubscribe_address" => unsubscribe_address(state, args),
        "list_subscriptions" => list_subscriptions(state),
        "register_abi" => register_abi(state, args),
        "create_keys" => create_keys(state, args).await,
        "get_wallet_status" => get_wallet_status(state, args).await,
        "set_wallet_policy" => set_wallet_policy(state, args).await,
        "get_wallet_policy" => get_wallet_policy(state, args).await,
        "deploy_wallet" => deploy_wallet(state, args).await,
        "send_transaction" => send_transaction(state, args).await,
        "confirm_transaction" => confirm_transaction(state, args).await,
        _ => bail!("unknown tool: {name}"),
    }
}

fn subscribe_address(state: &AppState, args: Value) -> Result<Value> {
    let address = args["address"].as_str().unwrap_or_default().to_string();
    if address.is_empty() {
        bail!("address is required");
    }

    let msg_types: std::collections::HashSet<MsgTypeFilter> = args
        .get("msg_types")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| match v.as_str()? {
                    "internal" => Some(MsgTypeFilter::Internal),
                    "ext_in" => Some(MsgTypeFilter::ExtIn),
                    "ext_out" => Some(MsgTypeFilter::ExtOut),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let method_names: std::collections::HashSet<String> = args
        .get("methods")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let rule = FilterRule {
        addresses: std::collections::HashSet::from([address.clone()]),
        msg_types,
        method_names,
    };

    state.filter_config.lock().rules.push(rule);
    tracing::info!(address, "subscribed");

    Ok(json!({ "subscribed": address }))
}

fn unsubscribe_address(state: &AppState, args: Value) -> Result<Value> {
    let address = args["address"].as_str().unwrap_or_default();
    if address.is_empty() {
        bail!("address is required");
    }

    let mut config = state.filter_config.lock();
    let before = config.rules.len();
    config.rules.retain(|r| !r.addresses.contains(address));
    let removed = before - config.rules.len();

    tracing::info!(address, removed, "unsubscribed");
    Ok(json!({ "unsubscribed": address, "rules_removed": removed }))
}

fn list_subscriptions(state: &AppState) -> Result<Value> {
    let config = state.filter_config.lock();
    Ok(serde_json::to_value(&*config)?)
}

fn register_abi(state: &AppState, args: Value) -> Result<Value> {
    let address = args["address"].as_str().unwrap_or_default();
    let abi_json = args["abi_json"].as_str().unwrap_or_default();
    if address.is_empty() || abi_json.is_empty() {
        bail!("address and abi_json are required");
    }

    state.abi_registry.lock().register(address, abi_json)?;
    tracing::info!(address, "ABI registered");
    Ok(json!({ "registered": address }))
}

/// Validate wallet_id: alphanumeric + hyphen/underscore only, no colons.
pub(crate) fn validate_wallet_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("wallet_id is required");
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        bail!("wallet_id must be alphanumeric, hyphens, or underscores only");
    }
    Ok(())
}

/// Validate signer_role against allowed enum.
pub(crate) fn validate_signer_role(role: &str) -> Result<()> {
    match role {
        "agent" | "controller" | "owner" => Ok(()),
        "" => bail!("signer_role is required"),
        _ => bail!("signer_role must be one of: agent, controller, owner"),
    }
}

/// Build the (wallet_id, role) composite object_key used for privkey/pubkey objects.
pub(crate) fn role_key(wallet_id: &str, role: &str) -> String {
    format!("{wallet_id}:{role}")
}

pub(crate) async fn create_keys(state: &AppState, args: Value) -> Result<Value> {
    let role = args["role"].as_str().unwrap_or_default();
    let wallet_id = args["wallet_id"].as_str().unwrap_or_default();
    validate_wallet_id(wallet_id)?;
    validate_signer_role(role)?;

    // Generate Ed25519 keypair
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let secret = hex::encode(signing_key.to_bytes());
    let public = hex::encode(signing_key.verifying_key().as_bytes());

    let obj_key = role_key(wallet_id, role);
    state
        .object_store()?
        .upsert(
            WALLET_PRIVKEY_KIND,
            &obj_key,
            json!({"value": secret, "role": role, "wallet_id": wallet_id}),
        )
        .await?;
    state
        .object_store()?
        .upsert(
            WALLET_PUBKEY_KIND,
            &obj_key,
            json!({"value": public, "role": role, "wallet_id": wallet_id}),
        )
        .await?;

    tracing::info!(wallet_id, role, "keys created");
    Ok(json!({
        "wallet_id": wallet_id,
        "role": role,
        "public_key": public,
    }))
}

/// Fetch the hex-encoded value field from a wallet pubkey/privkey object.
pub(crate) async fn get_wallet_key_value(
    state: &AppState,
    kind: &str,
    wallet_id: &str,
    role: &str,
) -> Result<Option<String>> {
    let obj_key = role_key(wallet_id, role);
    let body = state.object_store()?.get(kind, &obj_key).await?;
    Ok(body.and_then(|b| b.get("value").and_then(|v| v.as_str()).map(String::from)))
}

async fn get_wallet_status(state: &AppState, args: Value) -> Result<Value> {
    let wallet_id = args["wallet_id"].as_str().unwrap_or_default();
    validate_wallet_id(wallet_id)?;

    let agent_key = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "agent").await?;
    let controller_key =
        get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "controller").await?;
    let owner_key = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "owner").await?;

    let ready = agent_key.is_some() && controller_key.is_some() && owner_key.is_some();

    Ok(json!({
        "wallet_id": wallet_id,
        "ready": ready,
        "agent_key": agent_key,
        "controller_key": controller_key,
        "owner_key": owner_key,
    }))
}

async fn set_wallet_policy(state: &AppState, args: Value) -> Result<Value> {
    let raw_address = args["wallet_address"].as_str().unwrap_or_default();
    if raw_address.is_empty() {
        bail!("wallet_address is required");
    }
    // Key the policy by the CANONICAL account id, so a policy can't later be
    // missed by querying an equivalent alternate spelling (e.g. uppercase hex).
    let wallet_address = crate::wallet::policy::canon_dest(raw_address);

    let mut policy = args.clone();
    if let Some(obj) = policy.as_object_mut() {
        obj.insert("enabled".into(), json!(true));
        // Persist the canonical key in the metadata so get_wallet_policy's
        // exact-match query (also canonicalized) finds it.
        obj.insert("wallet_address".into(), json!(wallet_address));
    }

    let resp = state
        .memory_client()?
        .set_wallet_policy(&wallet_address, &policy)
        .await?;

    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            bail!("memory error storing policy: {err}");
        }
    }

    if resp.pointer("/result/isError").and_then(|v| v.as_bool()) == Some(true) {
        let err_text = resp
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown memory tool error");
        bail!("memory error storing policy: {err_text}");
    }

    Ok(json!({ "stored": wallet_address }))
}

async fn get_wallet_policy(state: &AppState, args: Value) -> Result<Value> {
    let raw_address = args["wallet_address"].as_str().unwrap_or_default();
    if raw_address.is_empty() {
        bail!("wallet_address is required");
    }
    // Look up by the SAME canonical key set_wallet_policy stored under.
    let wallet_address = crate::wallet::policy::canon_dest(raw_address);

    let result = state
        .memory_client()?
        .get_wallet_policy(&wallet_address)
        .await?;
    Ok(result)
}

pub(crate) async fn deploy_wallet(state: &AppState, args: Value) -> Result<Value> {
    let wallet_id = args["wallet_id"].as_str().unwrap_or_default();
    validate_wallet_id(wallet_id)?;

    let swarm_root = args["swarm_root_address"].as_str().unwrap_or_default();
    if swarm_root.is_empty() {
        bail!(
            "swarm_root_address is required — wallets must be deployed via SwarmRoot for DApp ID"
        );
    }

    // SwarmRoot owner private key — pre-seeded by namespace admin via memory_namespace_secret_set.
    // Delivered to us via X25519 sealed-box over /api/v1/agent/secrets/resolve.
    let root_owner_secret_name = format!("swarm_root:{swarm_root}:owner:privkey");
    let root_owner_secret = state
        .sealed_secrets()?
        .resolve_one(&root_owner_secret_name)
        .await
        .with_context(|| format!("resolving namespace secret '{root_owner_secret_name}'"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SwarmRoot owner key '{root_owner_secret_name}' not seeded. \
                 Admin must call memory_namespace_secret_set."
            )
        })?;

    let agent_pub = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "agent")
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent key not found for {wallet_id}"))?;
    let controller_pub = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "controller")
        .await?
        .ok_or_else(|| anyhow::anyhow!("controller key not found for {wallet_id}"))?;
    let owner_pub = get_wallet_key_value(state, WALLET_PUBKEY_KIND, wallet_id, "owner")
        .await?
        .ok_or_else(|| anyhow::anyhow!("owner key not found for {wallet_id}"))?;

    let swarmroot_abi = tvm_abi::Contract::load(
        include_str!("../../contracts/swarm/SwarmRoot.abi.json").as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("SwarmRoot ABI: {e}"))?;

    // 3-custodian wallet; reqConfirms defaults to 2 (governed) but the airegistry
    // operational buyer deploys with reqConfirms=1 (autonomous 1-sig spends).
    let req_confirms = args
        .get("req_confirms")
        .and_then(|v| v.as_u64())
        .unwrap_or(2);
    if !(1..=3).contains(&req_confirms) {
        bail!("req_confirms must be 1..=3 for a 3-custodian wallet");
    }
    let deploy_params = json!({
        "ownerPubkeys": [
            format!("0x{agent_pub}"),
            format!("0x{controller_pub}"),
            format!("0x{owner_pub}"),
        ],
        "ownerAddresses": [],
        "reqConfirms": req_confirms,
        "initialValue": "0",
        "walletPubkey": format!("0x{agent_pub}"),
    });

    let boc = wallet::transact::encode_external_call(
        swarm_root,
        &swarmroot_abi,
        "deployWallet",
        &deploy_params,
        &root_owner_secret,
    )?;

    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;

    let exit_code = resp["result"]["exit_code"].as_i64();
    let aborted = resp["result"]["aborted"].as_bool();
    if exit_code != Some(0) || aborted == Some(true) {
        bail!(
            "deploy failed: exit_code={}, aborted={}, response={}",
            exit_code.map_or("null".to_string(), |c| c.to_string()),
            aborted.map_or("null".to_string(), |a| a.to_string()),
            serde_json::to_string(&resp).unwrap_or_default(),
        );
    }

    let wallet_address = extract_deploy_address(&resp, &swarmroot_abi).map_err(|e| {
        anyhow::anyhow!(
            "deploy succeeded on-chain but failed to extract child wallet address: {e}. \
             Use getWalletAddress on SwarmRoot to retrieve it manually."
        )
    })?;

    state
        .object_store()?
        .upsert(
            WALLET_METADATA_KIND,
            wallet_id,
            json!({
                "wallet_id": wallet_id,
                "address": wallet_address,
                "swarm_root": swarm_root,
            }),
        )
        .await?;

    tracing::info!(
        wallet_id,
        address = wallet_address,
        swarm_root,
        "wallet deployed via SwarmRoot"
    );
    Ok(json!({
        "wallet_id": wallet_id,
        "address": wallet_address,
        "swarm_root": swarm_root,
        "send_response": resp,
    }))
}

async fn send_transaction(state: &AppState, args: Value) -> Result<Value> {
    let wallet_address = args["wallet_address"].as_str().unwrap_or_default();
    let dest = args["dest"].as_str().unwrap_or_default();
    let value_str = args["value"].as_str().unwrap_or_default();
    let bounce = args["bounce"].as_bool().unwrap_or(true);
    let signer_role = args["signer_role"].as_str().unwrap_or_default();
    let wallet_id = args["wallet_id"].as_str().unwrap_or_default();

    if wallet_address.is_empty() || dest.is_empty() {
        bail!("wallet_address and dest are required");
    }
    validate_wallet_id(wallet_id)?;
    validate_signer_role(signer_role)?;

    // Rate-limit + policy lookup keyed by the CANONICAL account id.
    let wallet_key = crate::wallet::policy::canon_dest(wallet_address);
    state.tx_rate_limiter.check(&wallet_key)?;

    if value_str.is_empty() {
        bail!("value is required");
    }

    let value: u128 = value_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid value: {value_str}"))?;

    // Policy enforcement: fail closed — if policy lookup fails, reject the transaction
    let policy_resp = state
        .memory_client()?
        .get_wallet_policy(&wallet_key)
        .await
        .map_err(|e| {
            tracing::error!(
                wallet_address,
                "policy lookup failed, rejecting transaction: {e}"
            );
            anyhow::anyhow!("policy lookup failed (fail closed): {e}")
        })?;

    if policy_resp
        .pointer("/result/isError")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        let err_text = policy_resp
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown memory tool error");
        tracing::error!(
            wallet_address,
            "policy lookup returned tool error, rejecting: {err_text}"
        );
        bail!("policy lookup failed (fail closed): {err_text}");
    }

    if let Some(policy) = wallet::policy::parse_policy_from_memory(&policy_resp) {
        policy.check(dest, value).map_err(|e| {
            tracing::warn!(
                wallet_address,
                dest,
                value = value_str,
                "policy rejected: {e}"
            );
            e
        })?;
        tracing::debug!(wallet_address, "policy check passed");
    }

    let secret = get_wallet_key_value(state, WALLET_PRIVKEY_KIND, wallet_id, signer_role)
        .await?
        .ok_or_else(|| anyhow::anyhow!("{signer_role} key not found for {wallet_id}"))?;

    let addr_int = parse_address(wallet_address)?;

    let boc = wallet::transact::encode_submit_transaction(&addr_int, dest, value, bounce, &secret)?;

    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;

    tracing::info!(wallet_id, dest, value = value_str, "transaction submitted");
    Ok(json!({
        "wallet_address": wallet_address,
        "dest": dest,
        "value": value_str,
        "policy_checked": true,
        "send_response": resp,
    }))
}

async fn confirm_transaction(state: &AppState, args: Value) -> Result<Value> {
    let wallet_address = args["wallet_address"].as_str().unwrap_or_default();
    let transaction_id = match args.get("transaction_id").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => bail!("transaction_id is required"),
    };
    let signer_role = args["signer_role"].as_str().unwrap_or_default();
    let wallet_id = args["wallet_id"].as_str().unwrap_or_default();

    if wallet_address.is_empty() {
        bail!("wallet_address is required");
    }
    validate_wallet_id(wallet_id)?;
    validate_signer_role(signer_role)?;
    // DApp id for reading the queued tx: explicit arg wins, else the wallet's
    // stored swarm_root (deploy_wallet persists it as the SwarmRoot-child DApp
    // id), else self-originating. Without the metadata fallback, a deploy_wallet
    // / treasury wallet's queued tx — which lives under the SwarmRoot DApp id —
    // would be read under the wrong origin and fail closed whenever a policy is
    // present, breaking the policy-protected second-signature flow.
    let effective_dapp_id: Option<String> = match args["dapp_id"].as_str().filter(|s| !s.is_empty())
    {
        Some(d) => Some(d.to_string()),
        None => state
            .object_store()?
            .get(WALLET_METADATA_KIND, wallet_id)
            .await?
            .and_then(|b| {
                b.get("swarm_root")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            }),
    };

    // Rate-limit + policy lookup are keyed by the CANONICAL account id, so an
    // alternate spelling can't dodge the limiter or miss the stored policy.
    let wallet_key = crate::wallet::policy::canon_dest(wallet_address);
    state.tx_rate_limiter.check(&wallet_key)?;

    let policy_resp = state.memory_client()?.get_wallet_policy(&wallet_key).await;
    match &policy_resp {
        Err(e) => {
            tracing::error!(wallet_address, "policy lookup failed on confirm: {e}");
            bail!("policy lookup failed: {e}");
        }
        Ok(resp) => {
            if resp.pointer("/result/isError").and_then(|v| v.as_bool()) == Some(true) {
                bail!("policy lookup returned error");
            }
            if let Some(policy) = wallet::policy::parse_policy_from_memory(resp) {
                if policy.policy_tier.as_deref() == Some("frozen") {
                    bail!("wallet is frozen — cannot confirm transactions");
                }
                // Releasing the second signature must face the SAME destination
                // + amount policy the first custodian's submit would — otherwise
                // a queued tx (possibly created outside this MCP path) to a
                // blocked destination or over the limit could be released here.
                // Fail closed: if the queued tx can't be read under the wallet's
                // DApp id, we can't verify it, so we refuse to confirm.
                let resolved = super::airegistry::read_queued_tx_for_policy(
                    state, wallet_address, effective_dapp_id.as_deref(), transaction_id,
                )
                .await
                .map_err(|e| anyhow::anyhow!("cannot read queued tx {transaction_id} to policy-check before confirm (fail closed; pass dapp_id?): {e}"))?;
                match resolved {
                    Some((dest, amount)) => {
                        policy.check(&dest, amount).map_err(|e| {
                            tracing::warn!(wallet_address, transaction_id, "confirm policy rejected: {e}");
                            e
                        })?;
                    }
                    None => bail!(
                        "queued transaction {transaction_id} not found on {wallet_address} under its DApp id — \
                         refusing to confirm an unverifiable transaction (fail closed)"
                    ),
                }
            }
        }
    }

    let secret = get_wallet_key_value(state, WALLET_PRIVKEY_KIND, wallet_id, signer_role)
        .await?
        .ok_or_else(|| anyhow::anyhow!("{signer_role} key not found for {wallet_id}"))?;

    let addr_int = parse_address(wallet_address)?;

    let boc = wallet::transact::encode_confirm_transaction(&addr_int, transaction_id, &secret)?;

    let resp = wallet::query::send_message(&state.http, &state.network.send_endpoint, &boc).await?;

    tracing::info!(
        wallet_id,
        transaction_id,
        signer_role,
        "transaction confirmed"
    );
    Ok(json!({
        "wallet_address": wallet_address,
        "transaction_id": transaction_id,
        "signer_role": signer_role,
        "send_response": resp,
    }))
}

/// Extract child wallet address from SwarmRoot.deployWallet ext_out_msgs.
fn extract_deploy_address(resp: &Value, swarmroot_abi: &tvm_abi::Contract) -> Result<String> {
    use tvm_block::Deserializable;

    let ext_out = resp["result"]["ext_out_msgs"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no ext_out_msg"))?;

    use base64::Engine;
    let boc = base64::engine::general_purpose::STANDARD.decode(ext_out)?;
    let cell = tvm_types::read_single_root_boc(&boc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = tvm_block::Message::construct_from_cell(cell).map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = msg.body().ok_or_else(|| anyhow::anyhow!("no body"))?;

    let func = swarmroot_abi
        .function("deployWallet")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let tokens = func
        .decode_output(body, false, true)
        .map_err(|e| anyhow::anyhow!("decode output: {e}"))?;

    for t in &tokens {
        if t.name == "walletAddress" {
            if let tvm_abi::TokenValue::Address(addr) = &t.value {
                return format_msg_address(addr);
            }
        }
    }
    anyhow::bail!("walletAddress not found in deployWallet output")
}

/// Format a TVM `MsgAddress` in canonical `workchain:hex` form that
/// `parse_address` can round-trip back to a `MsgAddressInt`.
fn format_msg_address(addr: &tvm_block::MsgAddress) -> Result<String> {
    match addr {
        tvm_block::MsgAddress::AddrStd(std) => {
            Ok(format!("{}:{:x}", std.workchain_id, std.address))
        }
        tvm_block::MsgAddress::AddrVar(var) => {
            Ok(format!("{}:{:x}", var.workchain_id, var.address))
        }
        other => anyhow::bail!("unsupported address kind in deployWallet output: {other:?}"),
    }
}

/// Parse "workchain:hex_address" into MsgAddressInt.
pub(crate) fn parse_address(addr_str: &str) -> Result<tvm_block::MsgAddressInt> {
    let parts: Vec<&str> = addr_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        bail!("invalid address format, expected workchain:hex");
    }
    let workchain: i8 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("bad workchain"))?;
    let hex_bytes = hex::decode(parts[1])?;
    if hex_bytes.len() != 32 {
        bail!("address must be 32 bytes");
    }
    tvm_block::MsgAddressInt::with_standart(
        None,
        workchain,
        tvm_types::AccountId::from_raw(hex_bytes, 256),
    )
    .map_err(|e| anyhow::anyhow!("address: {e}"))
}

use anyhow::Context as _;

/// Fail-closed wallet-policy gate, shared by `send_transaction` and the
/// airegistry consumer tools: if the policy lookup errors or the memory tool
/// reports an error, the spend is rejected. When a policy is present, it must
/// permit `(dest, value)`.
pub(crate) async fn enforce_wallet_policy(
    state: &AppState,
    wallet_address: &str,
    dest: &str,
    value: u128,
) -> Result<()> {
    // Look the policy up by the CANONICAL account id, so an alternate spelling
    // of the wallet can't miss its stored policy. (Destinations are canonicalized
    // inside WalletPolicy::check.)
    let wallet_key = crate::wallet::policy::canon_dest(wallet_address);
    let policy_resp = state
        .memory_client()?
        .get_wallet_policy(&wallet_key)
        .await
        .map_err(|e| {
            tracing::error!(wallet_address, "policy lookup failed, rejecting: {e}");
            anyhow::anyhow!("policy lookup failed (fail closed): {e}")
        })?;
    if policy_resp
        .pointer("/result/isError")
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        let err_text = policy_resp
            .pointer("/result/content/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown memory tool error");
        bail!("policy lookup failed (fail closed): {err_text}");
    }
    if let Some(policy) = wallet::policy::parse_policy_from_memory(&policy_resp) {
        policy.check(dest, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use parking_lot::Mutex;
    use serde_json::Value as JsonValue;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::client::crypto::public_key_b64;
    use crate::client::memory::MemoryClient;
    use crate::client::object_store::ObjectStoreClient;
    use crate::client::sealed_secrets::SealedSecretsClient;
    use crate::config::NetworkConfig;
    use crate::state::AppState;

    /// In-memory state for the mock gosh.memory server.
    #[derive(Default)]
    struct MemState {
        /// (object_kind, object_key) -> body JSON
        objects: HashMap<(String, String), JsonValue>,
        /// name -> plaintext value (namespace secrets, seeded by tests)
        namespace_secrets: HashMap<String, String>,
        /// last public_key sent to /api/v1/agent/public-key/register
        registered_pubkey_b64: Option<String>,
        /// asserted facts (wallet policies), for memory_query lookups
        facts: Vec<JsonValue>,
    }

    type SharedMem = Arc<Mutex<MemState>>;

    /// Encrypt plaintext to a GMS2 sealed-box envelope for an agent's public key.
    fn encrypt_namespace_secret(pubkey_b64: &str, plaintext: &str) -> String {
        use aes_gcm::aead::Aead;
        use aes_gcm::Aes256Gcm;
        use aes_gcm::KeyInit;
        use base64::Engine;
        use hkdf::Hkdf;
        use rand::rngs::OsRng;
        use rand::RngCore;
        use sha2::Sha256;
        use x25519_dalek::EphemeralSecret;

        const MAGIC: &[u8; 4] = b"GMS2";
        const INFO: &[u8] = b"gosh.memory/namespace-secret-delivery/v1";

        let recipient_bytes = base64::engine::general_purpose::STANDARD
            .decode(pubkey_b64)
            .unwrap();
        let arr: [u8; 32] = recipient_bytes.try_into().unwrap();
        let recipient_pk = PublicKey::from(arr);

        let mut rng = OsRng;
        let ephemeral = EphemeralSecret::random_from_rng(rng);
        let ephemeral_pk = PublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(&recipient_pk);

        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(INFO, &mut aes_key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext.as_bytes(),
            aad: INFO,
        };
        let ct = cipher.encrypt(nonce, payload).unwrap();

        let mut envelope = Vec::new();
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(ephemeral_pk.as_bytes());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ct);
        base64::engine::general_purpose::STANDARD.encode(envelope)
    }

    /// Start a mock gosh.memory server. Returns (base_url, shared mem state).
    async fn mock_memory_server() -> (String, SharedMem) {
        let state = Arc::new(Mutex::new(MemState::default()));

        let mcp_state = state.clone();
        let register_state = state.clone();
        let resolve_state = state.clone();

        let app = axum::Router::new()
            .route(
                "/mcp",
                axum::routing::post(move |body: axum::Json<JsonValue>| {
                    let state = mcp_state.clone();
                    async move {
                        let tool = body["params"]["name"].as_str().unwrap_or("").to_string();
                        let args = body["params"]["arguments"].clone();

                        let result_val = match tool.as_str() {
                            "memory_object_upsert" => {
                                let kind = args["object_kind"].as_str().unwrap_or("").to_string();
                                let key = args["object_key"].as_str().unwrap_or("").to_string();
                                let body = args["body"].clone();
                                state.lock().objects.insert((kind.clone(), key.clone()), body.clone());
                                json!({"ok": true, "object": {"object_kind": kind, "object_key": key, "body": body}})
                            }
                            "memory_object_get" => {
                                let kind = args["object_kind"].as_str().unwrap_or("").to_string();
                                let key = args["object_key"].as_str().unwrap_or("").to_string();
                                match state.lock().objects.get(&(kind.clone(), key.clone())).cloned() {
                                    Some(body) => json!({
                                        "ok": true,
                                        "object": {"object_kind": kind, "object_key": key, "body": body}
                                    }),
                                    None => json!({"error": "opaque object not found", "code": "NOT_FOUND"}),
                                }
                            }
                            "memory_object_list" => {
                                let kind = args["object_kind"].as_str().unwrap_or("").to_string();
                                let prefix = args["object_key_prefix"].as_str().unwrap_or("");
                                let objects: Vec<_> = state
                                    .lock()
                                    .objects
                                    .iter()
                                    .filter(|((k, key), _)| k == &kind && key.starts_with(prefix))
                                    .map(|((k, key), body)| json!({
                                        "object_kind": k, "object_key": key, "body": body
                                    }))
                                    .collect();
                                json!({"ok": true, "objects": objects})
                            }
                            "memory_query" => {
                                // Filter stored facts by metadata.wallet_address (the
                                // shape get_wallet_policy queries with).
                                let want = args.pointer("/filter/metadata.wallet_address").and_then(|v| v.as_str());
                                let facts: Vec<_> = state
                                    .lock()
                                    .facts
                                    .iter()
                                    .filter(|f| {
                                        want.is_none()
                                            || f.pointer("/metadata/wallet_address").and_then(|v| v.as_str()) == want
                                            || f.get("entities").and_then(|e| e.as_array()).map(|a| a.iter().any(|x| x.as_str() == want)).unwrap_or(false)
                                    })
                                    .cloned()
                                    .collect();
                                json!({ "facts": facts })
                            }
                            "memory_ingest_asserted_facts" => {
                                if let Some(fs) = args.get("facts").and_then(|v| v.as_array()) {
                                    state.lock().facts.extend(fs.iter().cloned());
                                }
                                json!({"ok": true, "ingested": 1})
                            }
                            _ => json!({"error": format!("unknown tool: {tool}"), "code": "UNKNOWN_TOOL"}),
                        };

                        axum::Json(json!({
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string(&result_val).unwrap()
                                }],
                                "isError": false,
                            }
                        }))
                    }
                }),
            )
            .route(
                "/api/v1/agent/public-key/register",
                axum::routing::post(move |body: axum::Json<JsonValue>| {
                    let state = register_state.clone();
                    async move {
                        let pk = body["public_key"].as_str().unwrap_or("").to_string();
                        state.lock().registered_pubkey_b64 = Some(pk);
                        axum::Json(json!({
                            "status": "ok",
                            "principal_id": "agent:test",
                            "algorithm": "x25519",
                            "key_id": "test-key-id",
                        }))
                    }
                }),
            )
            .route(
                "/api/v1/agent/secrets/resolve",
                axum::routing::post(move |body: axum::Json<JsonValue>| {
                    let state = resolve_state.clone();
                    async move {
                        let registered = state.lock().registered_pubkey_b64.clone();
                        let Some(pubkey_b64) = registered else {
                            return (
                                axum::http::StatusCode::UNAUTHORIZED,
                                axum::Json(json!({"error": "public key not registered"})),
                            );
                        };
                        let refs = body["refs"].as_array().cloned().unwrap_or_default();
                        let mut secrets = Vec::new();
                        for r in refs {
                            let name = r["name"].as_str().unwrap_or("").to_string();
                            let scope = r["scope"].as_str().unwrap_or("").to_string();
                            let plaintext = state.lock().namespace_secrets.get(&name).cloned();
                            if let Some(pt) = plaintext {
                                let ciphertext = encrypt_namespace_secret(&pubkey_b64, &pt);
                                secrets.push(json!({
                                    "name": name,
                                    "scope": scope,
                                    "algorithm": "x25519-hkdf-sha256-aes256gcm-v1",
                                    "key_id": "test-key-id",
                                    "ciphertext": ciphertext,
                                }));
                            }
                        }
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(json!({"secrets": secrets})),
                        )
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, state)
    }

    /// Build an AppState wired to the given mock memory URL + registered key.
    async fn build_state(url: &str) -> (AppState, Arc<StaticSecret>) {
        let rng = rand::rngs::OsRng;
        let secret = Arc::new(StaticSecret::random_from_rng(rng));
        let http = reqwest::Client::new();

        let memory_client = MemoryClient::new(
            url,
            "ackinacki",
            "ackinacki-agent",
            "default",
            "test-principal-token",
        )
        .with_transport_token(None);
        let object_store = ObjectStoreClient::new(
            http.clone(),
            url,
            "test-principal-token",
            None,
            "ackinacki",
            "default",
            "ackinacki-agent",
        );
        let sealed = SealedSecretsClient::new(
            http.clone(),
            url,
            "test-principal-token",
            None,
            "ackinacki",
            secret.clone(),
        );

        (
            AppState::new(
                memory_client,
                object_store,
                sealed,
                NetworkConfig::shellnet(),
            ),
            secret,
        )
    }

    /// Helper: bootstrap (register pubkey) + seed a namespace secret.
    async fn seed_namespace_secret(state: &AppState, mem: &SharedMem, name: &str, value: &str) {
        state
            .sealed_secrets()
            .unwrap()
            .register_public_key()
            .await
            .unwrap();
        mem.lock()
            .namespace_secrets
            .insert(name.to_string(), value.to_string());
    }

    /// State plus pre-registered pubkey for tests that need sealed_secrets to work.
    async fn test_state_with_memory() -> (AppState, SharedMem) {
        let (url, mem) = mock_memory_server().await;
        let (state, _secret) = build_state(&url).await;
        state
            .sealed_secrets()
            .unwrap()
            .register_public_key()
            .await
            .unwrap();
        (state, mem)
    }

    /// State with no mock server connectivity — for pure validation tests.
    fn test_state() -> AppState {
        let secret = Arc::new(StaticSecret::random_from_rng(rand::rngs::OsRng));
        let http = reqwest::Client::new();
        let memory_client = MemoryClient::new("http://127.0.0.1:9999", "k", "a", "s", "P");
        let object_store = ObjectStoreClient::new(
            http.clone(),
            "http://127.0.0.1:9999",
            "P",
            None,
            "k",
            "s",
            "a",
        );
        let sealed = SealedSecretsClient::new(
            http.clone(),
            "http://127.0.0.1:9999",
            "P",
            None,
            "k",
            secret,
        );
        AppState::new(
            memory_client,
            object_store,
            sealed,
            NetworkConfig::shellnet(),
        )
    }

    /// AI Registry read-only mode: no gosh.memory. The Memory accessors fail with
    /// an explicit message, and non-read tools are rejected up front by the
    /// dispatch gate (no chain or network is touched).
    #[tokio::test]
    async fn read_only_mode_rejects_memory_tools() {
        let state = AppState::new_read_only(NetworkConfig::shellnet());
        assert!(state.is_read_only());
        assert!(state.memory_client().is_err());
        assert!(state.object_store().is_err());
        assert!(state.sealed_secrets().is_err());
        // The accessor itself carries the explicit Memory-mode error.
        assert!(state
            .memory_client()
            .err()
            .unwrap()
            .to_string()
            .contains("Memory-backed mode required"));

        // Non-read tools are rejected by the read-only dispatch gate (the
        // capability contract), before any Memory access or network call.
        for (tool, args) in [
            ("get_wallet_status", json!({ "wallet_id": "w" })),
            (
                "set_wallet_policy",
                json!({ "wallet_address": "0:abc", "policy_tier": "frozen" }),
            ),
            ("create_keys", json!({ "wallet_id": "w", "role": "agent" })),
            (
                "deploy_contract",
                json!({ "signer_ref": { "kind": "object", "name": "x" } }),
            ),
            ("subscribe_address", json!({ "address": "0:abc" })),
        ] {
            let err = call_tool(&state, tool, args).await.unwrap_err().to_string();
            assert!(
                err.contains("not available in this mode"),
                "{tool} should be rejected in read-only mode, got: {err}"
            );
        }

        // call_contract reads are allowed, but a signed write (signer_ref) is
        // rejected up front (getter-only), not failed deep in signer resolution.
        let err = call_tool(
            &state,
            "call_contract",
            json!({
                "address": "0:abc",
                "method": "someWrite",
                "signer_ref": { "kind": "object", "name": "x" }
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("signed write") && err.contains("no-Memory mode"),
            "call_contract signer_ref must be rejected in read-only, got: {err}"
        );
    }

    /// In full mode the same tools do NOT short-circuit on the Memory accessor —
    /// they reach their real logic (here, get_wallet_status reads the object
    /// store and returns a not-ready status rather than a mode error).
    #[tokio::test]
    async fn full_mode_does_not_report_read_only() {
        let (state, _mem) = test_state_with_memory().await;
        assert!(!state.is_read_only());
        let out = call_tool(&state, "get_wallet_status", json!({ "wallet_id": "w" }))
            .await
            .unwrap();
        assert_eq!(out["ready"], json!(false));
    }

    // Minimal ABI JSON for register_abi tests.
    const TEST_ABI_JSON: &str = r#"{
        "ABI version": 2,
        "version": "2.4",
        "header": ["pubkey", "time", "expire"],
        "functions": [
            {
                "name": "confirmTransaction",
                "inputs": [{"name":"transactionId","type":"uint64"}],
                "outputs": []
            }
        ],
        "events": [],
        "fields": []
    }"#;

    // ---- list_tools ----

    #[test]
    fn stateless_payments_tools_list_adds_prepare_tools() {
        let names: std::collections::HashSet<_> = list_tools(ServeMode::StatelessPayments)
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect();
        // The read subset PLUS the three payment-prepare tools.
        for must in [
            "call_contract",
            "airegistry_get_lot",
            "airegistry_list_marketplace",
            "airegistry_prepare_user_buy_tokens",
            "airegistry_prepare_user_cancel",
            "airegistry_verify_payment_readiness",
        ] {
            assert!(names.contains(must), "stateless must serve {must}");
        }
        // Still no wallet / deploy / Memory-backed write tool.
        for forbidden in [
            "deploy_contract",
            "create_keys",
            "airegistry_buy_tokens",
            "airegistry_create_token_lot",
        ] {
            assert!(
                !names.contains(forbidden),
                "stateless must not serve {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn stateless_mode_gate_and_key_guard() {
        let state = AppState::new_stateless_payments(NetworkConfig::shellnet());
        assert_eq!(state.mode(), ServeMode::StatelessPayments);
        // A non-served (Memory-backed) tool is rejected at the gate — no network.
        let err = call_tool(
            &state,
            "create_keys",
            json!({ "wallet_id": "w", "role": "agent" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("not available in this mode"), "got: {err}");
        // A payment tool carrying key material is rejected before any chain call.
        let err2 = call_tool(
            &state,
            "airegistry_prepare_user_buy_tokens",
            json!({ "token_contract_address": "0:abc", "buyer_wallet_address": "0:def", "shell_amount": "1", "secret": "leak" }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err2.contains("never accept key material"), "got: {err2}");
    }

    #[test]
    fn read_only_tools_list_is_the_safe_subset() {
        let tools = list_tools(ServeMode::ReadOnly);
        let names: std::collections::HashSet<_> =
            tools.iter().filter_map(|t| t["name"].as_str()).collect();
        // Only chain-first read tools are advertised — incl. the pure-read
        // readiness verifier, but NOT the payment-prepare tools.
        assert_eq!(
            names,
            std::collections::HashSet::from([
                "call_contract",
                "airegistry_resolve_model",
                "airegistry_get_manifest",
                "airegistry_get_lot",
                "airegistry_get_entitlement",
                "airegistry_list_marketplace",
                "airegistry_verify_payment_readiness",
            ])
        );
        assert!(!names.contains("airegistry_prepare_user_buy_tokens"));
        // No wallet / deploy / policy / subscription / write tool leaks in.
        for forbidden in [
            "deploy_contract",
            "create_keys",
            "set_wallet_policy",
            "subscribe_address",
            "register_abi",
            "airegistry_create_token_lot",
        ] {
            assert!(
                !names.contains(forbidden),
                "read-only must not advertise {forbidden}"
            );
        }
        // call_contract is advertised getter-only: no signed-write `signer_ref`.
        let call_contract = tools
            .iter()
            .find(|t| t["name"] == "call_contract")
            .expect("call_contract in read-only list");
        assert!(
            call_contract
                .pointer("/inputSchema/properties/signer_ref")
                .is_none(),
            "read-only call_contract must not advertise the signer_ref write path"
        );
    }

    #[test]
    fn list_tools_returns_all_tools() {
        let tools = list_tools(ServeMode::Full);
        // 11 base (subscribe/abi/wallet) + 23 airegistry (§9 full surface).
        assert_eq!(tools.len(), 34);
        let names: std::collections::HashSet<_> =
            tools.iter().filter_map(|t| t["name"].as_str()).collect();
        for expected in [
            "call_contract",
            "deploy_contract",
            "airegistry_register_model",
            "airegistry_create_token_lot",
            "airegistry_bill_session",
            "airegistry_deploy_buyer",
            "airegistry_fund_buyer",
            "airegistry_buy_tokens",
            "airegistry_cancel",
            "airegistry_withdraw_shell",
            "airegistry_get_entitlement",
        ] {
            assert!(
                names.contains(expected),
                "missing airegistry tool: {expected}"
            );
        }
    }

    #[test]
    fn each_tool_has_name_description_schema() {
        let tools = list_tools(ServeMode::Full);
        for tool in &tools {
            assert!(tool.get("name").is_some(), "tool missing name");
            assert!(tool["name"].as_str().is_some(), "tool name is not a string");
            assert!(
                tool.get("description").is_some(),
                "tool missing description"
            );
            assert!(
                tool.get("inputSchema").is_some(),
                "tool missing inputSchema"
            );
        }
    }

    #[test]
    fn tool_names_are_correct() {
        let tools = list_tools(ServeMode::Full);
        let names: std::collections::HashSet<_> =
            tools.iter().filter_map(|t| t["name"].as_str()).collect();
        for expected in &[
            "subscribe_address",
            "unsubscribe_address",
            "list_subscriptions",
            "register_abi",
            "create_keys",
            "get_wallet_status",
            "set_wallet_policy",
            "get_wallet_policy",
            "deploy_wallet",
            "send_transaction",
            "confirm_transaction",
        ] {
            assert!(names.contains(expected), "missing tool: {expected}");
        }
        assert!(
            !names.contains("import_secret"),
            "import_secret was removed"
        );
    }

    // ---- subscribe / unsubscribe / list ----

    #[test]
    fn subscribe_address_valid() {
        let state = test_state();
        let result = subscribe_address(&state, json!({"address": "0:abc"}));
        assert!(result.is_ok());
        assert_eq!(state.filter_config.lock().rules.len(), 1);
    }

    #[test]
    fn subscribe_address_empty_address_error() {
        let state = test_state();
        let result = subscribe_address(&state, json!({"address": ""}));
        assert!(result.is_err());
    }

    #[test]
    fn subscribe_address_missing_address_error() {
        let state = test_state();
        let result = subscribe_address(&state, json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn subscribe_address_with_msg_types() {
        let state = test_state();
        let result = subscribe_address(
            &state,
            json!({"address": "0:abc", "msg_types": ["internal", "ext_in"]}),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn subscribe_address_with_methods() {
        let state = test_state();
        let result =
            subscribe_address(&state, json!({"address": "0:abc", "methods": ["transfer"]}));
        assert!(result.is_ok());
    }

    #[test]
    fn unsubscribe_address_removes_correct_rules() {
        let state = test_state();
        subscribe_address(&state, json!({"address": "0:abc"})).unwrap();
        subscribe_address(&state, json!({"address": "0:def"})).unwrap();
        let result = unsubscribe_address(&state, json!({"address": "0:abc"}));
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["rules_removed"], 1);
        assert_eq!(state.filter_config.lock().rules.len(), 1);
    }

    #[test]
    fn unsubscribe_address_nonexistent_returns_zero() {
        let state = test_state();
        subscribe_address(&state, json!({"address": "0:abc"})).unwrap();
        let result = unsubscribe_address(&state, json!({"address": "0:xyz"}));
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["rules_removed"], 0);
    }

    #[test]
    fn unsubscribe_address_empty_error() {
        let state = test_state();
        let result = unsubscribe_address(&state, json!({"address": ""}));
        assert!(result.is_err());
    }

    #[test]
    fn list_subscriptions_empty_state() {
        let state = test_state();
        let result = list_subscriptions(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn list_subscriptions_after_adding_rules() {
        let state = test_state();
        subscribe_address(&state, json!({"address": "0:aaa"})).unwrap();
        let result = list_subscriptions(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn subscribe_multiple_then_unsubscribe_all() {
        let state = test_state();
        subscribe_address(&state, json!({"address": "0:a"})).unwrap();
        subscribe_address(&state, json!({"address": "0:b"})).unwrap();
        subscribe_address(&state, json!({"address": "0:c"})).unwrap();
        assert_eq!(state.filter_config.lock().rules.len(), 3);
        unsubscribe_address(&state, json!({"address": "0:a"})).unwrap();
        unsubscribe_address(&state, json!({"address": "0:b"})).unwrap();
        unsubscribe_address(&state, json!({"address": "0:c"})).unwrap();
        assert_eq!(state.filter_config.lock().rules.len(), 0);
    }

    // ---- register_abi ----

    #[test]
    fn register_abi_valid() {
        let state = test_state();
        let result = register_abi(
            &state,
            json!({"address": "0:abc", "abi_json": TEST_ABI_JSON}),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn register_abi_empty_address_error() {
        let state = test_state();
        let result = register_abi(&state, json!({"address": "", "abi_json": TEST_ABI_JSON}));
        assert!(result.is_err());
    }

    #[test]
    fn register_abi_empty_abi_json_error() {
        let state = test_state();
        let result = register_abi(&state, json!({"address": "0:abc", "abi_json": ""}));
        assert!(result.is_err());
    }

    #[test]
    fn register_abi_invalid_json_error() {
        let state = test_state();
        let result = register_abi(&state, json!({"address": "0:abc", "abi_json": "not json"}));
        assert!(result.is_err());
    }

    // ---- create_keys / get_wallet_status (against mock memory) ----

    #[tokio::test]
    async fn create_keys_valid() {
        let (state, _mem) = test_state_with_memory().await;
        let result = create_keys(&state, json!({"role": "agent", "wallet_id": "wallet1"})).await;
        assert!(result.is_ok(), "create_keys failed: {result:?}");
        let val = result.unwrap();
        assert_eq!(val["wallet_id"], "wallet1");
        assert_eq!(val["role"], "agent");
        let pk = val["public_key"].as_str().unwrap();
        assert_eq!(pk.len(), 64);
        assert!(pk.chars().all(|c: char| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn create_keys_empty_role_error() {
        let state = test_state();
        let result = create_keys(&state, json!({"role": "", "wallet_id": "wallet1"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_keys_empty_wallet_id_error() {
        let state = test_state();
        let result = create_keys(&state, json!({"role": "agent", "wallet_id": ""})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_keys_stores_privkey_and_pubkey() {
        let (state, mem) = test_state_with_memory().await;
        create_keys(&state, json!({"role": "agent", "wallet_id": "w1"}))
            .await
            .unwrap();
        let priv_present = mem
            .lock()
            .objects
            .contains_key(&(WALLET_PRIVKEY_KIND.to_string(), "w1:agent".to_string()));
        let pub_present = mem
            .lock()
            .objects
            .contains_key(&(WALLET_PUBKEY_KIND.to_string(), "w1:agent".to_string()));
        assert!(priv_present);
        assert!(pub_present);
    }

    #[tokio::test]
    async fn get_wallet_status_no_keys_not_ready() {
        let (state, _mem) = test_state_with_memory().await;
        let result = get_wallet_status(&state, json!({"wallet_id": "w1"}))
            .await
            .unwrap();
        assert_eq!(result["ready"], false);
        assert!(result["agent_key"].is_null());
        assert!(result["controller_key"].is_null());
        assert!(result["owner_key"].is_null());
    }

    #[tokio::test]
    async fn get_wallet_status_all_keys_ready() {
        let (state, _mem) = test_state_with_memory().await;
        create_keys(&state, json!({"role": "agent", "wallet_id": "w1"}))
            .await
            .unwrap();
        create_keys(&state, json!({"role": "controller", "wallet_id": "w1"}))
            .await
            .unwrap();
        create_keys(&state, json!({"role": "owner", "wallet_id": "w1"}))
            .await
            .unwrap();
        let result = get_wallet_status(&state, json!({"wallet_id": "w1"}))
            .await
            .unwrap();
        assert_eq!(result["ready"], true);
    }

    #[tokio::test]
    async fn get_wallet_status_partial_keys_not_ready() {
        let (state, _mem) = test_state_with_memory().await;
        create_keys(&state, json!({"role": "agent", "wallet_id": "w1"}))
            .await
            .unwrap();
        create_keys(&state, json!({"role": "controller", "wallet_id": "w1"}))
            .await
            .unwrap();
        // Skip owner
        let result = get_wallet_status(&state, json!({"wallet_id": "w1"}))
            .await
            .unwrap();
        assert_eq!(result["ready"], false);
        assert!(result["agent_key"].as_str().is_some());
        assert!(result["controller_key"].as_str().is_some());
        assert!(result["owner_key"].is_null());
    }

    #[tokio::test]
    async fn get_wallet_status_empty_wallet_id_error() {
        let state = test_state();
        let result = get_wallet_status(&state, json!({"wallet_id": ""})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_keys_generates_unique_keypairs() {
        let (state, _mem) = test_state_with_memory().await;
        let res1 = create_keys(&state, json!({"role": "agent", "wallet_id": "w1"}))
            .await
            .unwrap();
        let res2 = create_keys(&state, json!({"role": "controller", "wallet_id": "w1"}))
            .await
            .unwrap();
        assert_ne!(res1["public_key"], res2["public_key"]);
    }

    // ---- deploy_wallet error paths (object store + sealed secrets) ----

    #[tokio::test]
    async fn deploy_wallet_missing_swarm_root() {
        let state = test_state();
        let result = call_tool(&state, "deploy_wallet", json!({"wallet_id": "test1"})).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("swarm_root_address is required"));
    }

    #[tokio::test]
    async fn deploy_wallet_empty_id() {
        let state = test_state();
        let result = call_tool(
            &state,
            "deploy_wallet",
            json!({"wallet_id": "", "swarm_root_address": "0:abc"}),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn deploy_wallet_missing_root_owner_secret() {
        let (state, _mem) = test_state_with_memory().await;
        let root_addr = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        create_keys(&state, json!({"role": "agent", "wallet_id": "w1"}))
            .await
            .unwrap();
        create_keys(&state, json!({"role": "controller", "wallet_id": "w1"}))
            .await
            .unwrap();
        create_keys(&state, json!({"role": "owner", "wallet_id": "w1"}))
            .await
            .unwrap();
        let result = call_tool(
            &state,
            "deploy_wallet",
            json!({"wallet_id": "w1", "swarm_root_address": root_addr}),
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SwarmRoot owner key") && err.contains("not seeded"));
    }

    #[tokio::test]
    async fn deploy_wallet_missing_wallet_keys_but_root_seeded() {
        let (state, mem) = test_state_with_memory().await;
        let root_addr = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        seed_namespace_secret(
            &state,
            &mem,
            &format!("swarm_root:{root_addr}:owner:privkey"),
            &hex::encode([0xABu8; 32]),
        )
        .await;
        let result = call_tool(
            &state,
            "deploy_wallet",
            json!({"wallet_id": "w1", "swarm_root_address": root_addr}),
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("key not found"),
            "expected wallet-key error, got: {err}"
        );
    }

    // ---- send / confirm transaction validation ----

    #[tokio::test]
    async fn send_transaction_missing_fields() {
        let state = test_state();
        let result = call_tool(&state, "send_transaction", json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn confirm_transaction_missing_fields() {
        let state = test_state();
        let result = call_tool(&state, "confirm_transaction", json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_tool_unknown_tool_error() {
        let state = test_state();
        let result = call_tool(&state, "nonexistent_tool", json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown tool"));
    }

    #[tokio::test]
    async fn call_tool_dispatches_subscribe() {
        let state = test_state();
        let result = call_tool(&state, "subscribe_address", json!({"address": "0:test"})).await;
        assert!(result.is_ok());
        assert_eq!(state.filter_config.lock().rules.len(), 1);
    }

    #[tokio::test]
    async fn call_tool_dispatches_list_subscriptions() {
        let state = test_state();
        let result = call_tool(&state, "list_subscriptions", json!({})).await;
        assert!(result.is_ok());
    }

    // ---- parse_address ----

    #[test]
    fn parse_address_valid() {
        let addr = "0:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(parse_address(addr).is_ok());
    }

    #[test]
    fn parse_address_negative_workchain() {
        let addr = "-1:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(parse_address(addr).is_ok());
    }

    #[test]
    fn parse_address_invalid_format() {
        assert!(parse_address("no_colon").is_err());
        assert!(parse_address("").is_err());
        assert!(parse_address("0:tooshort").is_err());
    }

    // ---- format_msg_address ↔ parse_address roundtrip ----
    //
    // Regression guard: extract_deploy_address used to call
    // `addr.get_address().to_string()` which returned a SliceData diagnostic
    // string (`SliceData{...}`), not a workchain:hex address. The stored value
    // then failed parse_address in subsequent send_transaction calls.

    #[test]
    fn format_msg_address_addrstd_roundtrips_through_parse_address() {
        // Build a MsgAddrStd directly and confirm the formatted form parses back.
        let raw = hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap();
        let account_id = tvm_types::AccountId::from_raw(raw.clone(), 256);
        let std = tvm_block::MsgAddrStd {
            anycast: None,
            workchain_id: 0,
            address: account_id,
        };
        let msg_addr = tvm_block::MsgAddress::AddrStd(std);

        let formatted = format_msg_address(&msg_addr).expect("format_msg_address");
        assert!(
            formatted.starts_with("0:"),
            "expected workchain:hex form, got {formatted}"
        );
        assert_eq!(
            formatted.len(),
            "0:".len() + 64,
            "expected 64 hex chars in account id, got {formatted}"
        );
        // The critical assertion: the round-trip must succeed.
        let parsed = parse_address(&formatted)
            .expect("parse_address must accept the format produced by format_msg_address");
        // Sanity: formatting the parsed value yields the same string.
        if let tvm_block::MsgAddressInt::AddrStd(parsed_std) = parsed {
            assert_eq!(parsed_std.workchain_id, 0);
            assert_eq!(parsed_std.address.get_bytestring(0), raw);
        } else {
            panic!("expected AddrStd after roundtrip");
        }
    }

    #[test]
    fn format_msg_address_addr_none_errors() {
        let msg_addr = tvm_block::MsgAddress::AddrNone;
        assert!(format_msg_address(&msg_addr).is_err());
    }

    // ---- rate limiter ----

    #[test]
    fn rate_limiter_allows_under_limit() {
        let rl = TxRateLimiter::new();
        for _ in 0..10 {
            assert!(rl.check("0:wallet1").is_ok());
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let rl = TxRateLimiter::new();
        for _ in 0..10 {
            rl.check("0:wallet1").unwrap();
        }
        assert!(rl.check("0:wallet1").is_err());
    }

    #[test]
    fn rate_limiter_separate_wallets() {
        let rl = TxRateLimiter::new();
        for _ in 0..10 {
            rl.check("0:wallet1").unwrap();
        }
        assert!(rl.check("0:wallet2").is_ok());
    }

    #[test]
    fn rate_limiter_tracks_buckets() {
        let rl = TxRateLimiter::new();
        rl.check("0:a").unwrap();
        rl.check("0:b").unwrap();
        rl.check("0:c").unwrap();
        assert_eq!(rl.bucket_count(), 3);
    }

    // ---- validate helpers ----

    #[test]
    fn validate_wallet_id_valid() {
        assert!(validate_wallet_id("my-wallet-01").is_ok());
        assert!(validate_wallet_id("wallet_test").is_ok());
        assert!(validate_wallet_id("abc123").is_ok());
    }

    #[test]
    fn validate_wallet_id_empty() {
        assert!(validate_wallet_id("").is_err());
    }

    #[test]
    fn validate_wallet_id_rejects_colons() {
        assert!(validate_wallet_id("wallet:evil").is_err());
    }

    #[test]
    fn validate_wallet_id_rejects_slashes() {
        assert!(validate_wallet_id("../../etc").is_err());
    }

    #[test]
    fn validate_wallet_id_rejects_spaces() {
        assert!(validate_wallet_id("wallet evil").is_err());
    }

    #[test]
    fn validate_signer_role_valid() {
        assert!(validate_signer_role("agent").is_ok());
        assert!(validate_signer_role("controller").is_ok());
        assert!(validate_signer_role("owner").is_ok());
    }

    #[test]
    fn validate_signer_role_rejects_unknown() {
        assert!(validate_signer_role("admin").is_err());
        assert!(validate_signer_role("root").is_err());
    }

    #[test]
    fn validate_signer_role_empty() {
        assert!(validate_signer_role("").is_err());
    }

    // ---- sealed_secrets register + resolve roundtrip ----

    #[tokio::test]
    async fn sealed_secrets_register_and_resolve_roundtrip() {
        let (url, mem) = mock_memory_server().await;
        let (state, _secret) = build_state(&url).await;
        state
            .sealed_secrets()
            .unwrap()
            .register_public_key()
            .await
            .unwrap();
        mem.lock()
            .namespace_secrets
            .insert("test:secret".to_string(), "the_value".to_string());
        let resolved = state
            .sealed_secrets()
            .unwrap()
            .resolve_one("test:secret")
            .await
            .unwrap();
        assert_eq!(resolved.as_deref(), Some("the_value"));

        // unknown name → None
        let unknown = state
            .sealed_secrets()
            .unwrap()
            .resolve_one("not:there")
            .await
            .unwrap();
        assert!(unknown.is_none());
    }

    // ---- public_key_b64 quick sanity ----

    #[test]
    fn pubkey_b64_decode_to_32_bytes() {
        use base64::Engine;
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = public_key_b64(&secret);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(pk)
            .unwrap();
        assert_eq!(raw.len(), 32);
    }

    // ---- airegistry consumer spend is policy-gated ----

    /// Regression: the consumer wallet-spend path (`airegistry_buy_tokens`) MUST
    /// pass the same fail-closed policy gate as `send_transaction`. The object
    /// store (oper-wallet pointer + custodian keys) is live on the mock but the
    /// policy lookup is unreachable — the spend must be rejected fail-closed
    /// BEFORE any chain interaction. (deploy_contract no longer funds from a
    /// wallet — it uses the free testnet Giver per §8 — so the wallet-policy gate
    /// lives on the consumer spend tools, which is where it is asserted here.)
    #[tokio::test]
    async fn airegistry_consumer_spend_is_policy_gated_fail_closed() {
        let (mock_url, _mem) = mock_memory_server().await;
        let http = reqwest::Client::new();
        let secret = Arc::new(StaticSecret::random_from_rng(rand::rngs::OsRng));
        // memory_client points at a dead port ⇒ policy lookup fails closed.
        let memory_client = MemoryClient::new(
            "http://127.0.0.1:9",
            "ackinacki",
            "ackinacki-agent",
            "default",
            "test-principal-token",
        )
        .with_transport_token(None);
        let object_store = ObjectStoreClient::new(
            http.clone(),
            &mock_url,
            "test-principal-token",
            None,
            "ackinacki",
            "default",
            "ackinacki-agent",
        );
        let sealed = SealedSecretsClient::new(
            http.clone(),
            &mock_url,
            "test-principal-token",
            None,
            "ackinacki",
            secret,
        );
        let state = AppState::new(
            memory_client,
            object_store,
            sealed,
            NetworkConfig::shellnet(),
        );

        // Seed the operational wallet pointer + custodian keys on the live store.
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let spub = hex::encode(sk.verifying_key().as_bytes());
        let ssec = hex::encode(sk.to_bytes());
        let oper_addr = format!("0:{}", "11".repeat(32));
        let store = crate::airegistry::store::Store::new(&state);
        store.put_oper_wallet("oper", &oper_addr).await.unwrap();
        state
            .object_store()
            .unwrap()
            .upsert(
                WALLET_PUBKEY_KIND,
                &role_key("oper", "agent"),
                json!({ "value": spub }),
            )
            .await
            .unwrap();
        state
            .object_store()
            .unwrap()
            .upsert(
                WALLET_PRIVKEY_KIND,
                &role_key("oper", "agent"),
                json!({ "value": ssec }),
            )
            .await
            .unwrap();

        let args = json!({
            "oper_wallet_id": "oper",
            "signer_role": "agent",
            "token_contract_address": format!("0:{}", "22".repeat(32)),
            "shell_amount": "5000"
        });
        let err = call_tool(&state, "airegistry_buy_tokens", args)
            .await
            .expect_err("a wallet spend must be rejected when policy is unavailable")
            .to_string();
        assert!(
            err.contains("policy"),
            "expected a fail-closed policy rejection, got: {err}"
        );
    }

    /// Positive policy enforcement: a STORED frozen policy must reject an
    /// airegistry consumer spend (regression for the parser that previously
    /// dropped the MCP-wrapped policy envelope and let spends through).
    #[tokio::test]
    async fn airegistry_buy_tokens_rejected_by_stored_policy() {
        let (state, _mem) = test_state_with_memory().await;
        let store = crate::airegistry::store::Store::new(&state);

        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let spub = hex::encode(sk.verifying_key().as_bytes());
        let ssec = hex::encode(sk.to_bytes());
        let oper_addr = format!("0:{}", "11".repeat(32));
        store.put_oper_wallet("oper", &oper_addr).await.unwrap();
        state
            .object_store()
            .unwrap()
            .upsert(
                WALLET_PUBKEY_KIND,
                &role_key("oper", "agent"),
                json!({ "value": spub }),
            )
            .await
            .unwrap();
        state
            .object_store()
            .unwrap()
            .upsert(
                WALLET_PRIVKEY_KIND,
                &role_key("oper", "agent"),
                json!({ "value": ssec }),
            )
            .await
            .unwrap();

        // Store a frozen policy for the operational wallet.
        state
            .memory_client()
            .unwrap()
            .set_wallet_policy(
                &oper_addr,
                &json!({ "wallet_address": oper_addr, "policy_tier": "frozen", "enabled": true }),
            )
            .await
            .unwrap();

        let args = json!({
            "oper_wallet_id": "oper",
            "signer_role": "agent",
            "token_contract_address": format!("0:{}", "22".repeat(32)),
            "shell_amount": "5000"
        });
        let err = call_tool(&state, "airegistry_buy_tokens", args)
            .await
            .expect_err("a frozen-wallet spend must be rejected")
            .to_string();
        assert!(
            err.contains("frozen"),
            "expected the stored frozen policy to reject the spend, got: {err}"
        );
    }

    /// token_lot pointer-cache: the `token_lot` record round-trips through the
    /// gosh.memory object store (an optional best-effort cache) carrying the
    /// package integrity hash. The package itself lives on-chain in
    /// ManifestMetadata; this only asserts the cached hash linkage.
    #[tokio::test]
    async fn airegistry_token_lot_roundtrip() {
        let (state, _mem) = test_state_with_memory().await;
        let store = crate::airegistry::store::Store::new(&state);

        let sha = "da30f4dab60dc59788d753457c4575b2d1e0a18fb3696fe550934d623ef38481";
        let sr = "0:1111111111111111111111111111111111111111111111111111111111111111";
        let rm = "0:2222222222222222222222222222222222222222222222222222222222222222";
        let tc = "0:3333333333333333333333333333333333333333333333333333333333333333";
        store
            .put_token_lot(
                sr,
                rm,
                "abcd",
                1,
                tc,
                "GPT-X",
                "https://api.example.com",
                Some(sha),
            )
            .await
            .unwrap();
        let key = store.token_lot_key(sr, rm, "abcd", 1);
        let lot = state
            .object_store()
            .unwrap()
            .get(crate::airegistry::store::KIND_TOKEN_LOT, &key)
            .await
            .unwrap()
            .expect("token_lot stored");
        assert_eq!(lot.get("address").and_then(|v| v.as_str()), Some(tc));
        assert_eq!(
            lot.get("model_name").and_then(|v| v.as_str()),
            Some("GPT-X")
        );
        assert_eq!(lot.get("root_model").and_then(|v| v.as_str()), Some(rm));
        // The lot is linked to the package by its content hash.
        assert_eq!(
            lot.get("package_sha256").and_then(|v| v.as_str()),
            Some(sha)
        );
    }
}
