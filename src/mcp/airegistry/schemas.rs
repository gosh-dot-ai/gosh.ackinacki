// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! JSON-Schema declarations for the airegistry MCP tools (§9).

use serde_json::{json, Value};

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

/// Like [`obj`] but also declares an `anyOf` of mutually-substitutable required
/// groups — e.g. "exactly one of `package` / `api_schema_json` must be present".
/// Keeps the advertised schema honest with handlers that accept aliased fields.
fn obj_any_of_required(props: Value, required: &[&str], any_of: &[&[&str]]) -> Value {
    let mut schema = obj(props, required);
    schema["anyOf"] = Value::Array(
        any_of
            .iter()
            .map(|grp| json!({ "required": grp }))
            .collect(),
    );
    schema
}

const ROLE: &str = "agent|controller|owner";

/// A `signer_ref` schema fragment (creator seller key, §5).
fn signer_ref() -> Value {
    json!({
        "type": "object",
        "description": "Where the seller signing key lives (§5)",
        "properties": {
            "kind": { "type": "string", "enum": ["object", "namespace_secret"] },
            "name": { "type": "string" }
        },
        "required": ["kind", "name"]
    })
}

pub fn list_airegistry_tools() -> Vec<Value> {
    let role =
        json!({ "type": "string", "enum": ["agent", "controller", "owner"], "description": ROLE });
    vec![
        // ---- §9.1 generic ----
        json!({
            "name": "call_contract",
            "description": "Run an ABI getter (read) on a contract; OR, when a `signer_ref` is given, send a signed external-inbound call (write). Use `contract` (SuperRoot|RootModel|TokenContract|ManifestMetadata) or raw `abi_json`. Currency-attaching calls (buyTokens) go through the consumer tools, not here.",
            "inputSchema": obj(json!({
                "address": { "type": "string" },
                "contract": { "type": "string", "enum": ["SuperRoot", "RootModel", "TokenContract", "ManifestMetadata"] },
                "abi_json": { "type": "string" },
                "method": { "type": "string" },
                "params": { "type": "object" },
                "signer_ref": signer_ref(),
                "dapp_id": { "type": "string" }
            }), &["address", "method"])
        }),
        json!({
            "name": "deploy_contract",
            "description": "Deterministic stateInit deploy (signed by `signer_ref`), funded on shellnet by the Giver (§8), waits Active. Use `contract` for an embedded airegistry artifact or `abi_json`+`tvc_b64`. `var_init` = static init fields, `constructor_params` = ctor args.",
            "inputSchema": obj(json!({
                "contract": { "type": "string", "enum": ["SuperRoot", "RootModel", "TokenContract", "ManifestMetadata"] },
                "abi_json": { "type": "string" },
                "tvc_b64": { "type": "string" },
                "var_init": { "type": "object" },
                "constructor_params": { "type": "object" },
                "signer_ref": signer_ref()
            }), &["signer_ref"])
        }),
        // ---- §9.2 creator ----
        json!({
            "name": "airegistry_deploy_super_root",
            "description": "Creator: deploy a SuperRoot(pubkey, rootModelCode, manifestCode) (usually host-provided). Funded via Giver; persists the super_root pointer.",
            "inputSchema": obj(json!({ "pubkey": { "type": "string" }, "signer_ref": signer_ref() }), &["pubkey", "signer_ref"])
        }),
        json!({
            "name": "airegistry_register_model",
            "description": "Creator: deploy a RootModel for `owner_pubkey` under `super_root_address` (RootModel self-registers → RootRegistered). Persists the root_model pointer.",
            "inputSchema": obj(json!({
                "super_root_address": { "type": "string" },
                "owner_pubkey": { "type": "string" },
                "signer_ref": signer_ref()
            }), &["super_root_address", "owner_pubkey", "signer_ref"])
        }),
        json!({
            "name": "airegistry_set_manifest",
            "description": "Creator: store the FULL canonical package ON-CHAIN in ManifestMetadata (the authoritative, blockchain-only source of truth — no off-chain/memory package store). The package is split into <=32KB indexed chunks written via setApiSchemaChunk (each an O(1) write, so any size fits). Returns the manifest address, byte size, chunk count, and sha256.",
            "inputSchema": obj_any_of_required(json!({
                "super_root_address": { "type": "string" },
                "root_model_address": { "type": "string" },
                "owner_pubkey": { "type": "string" },
                "package": { "type": "string", "description": "Full canonical package content stored verbatim on-chain (alias: api_schema_json)" },
                "api_schema_json": { "type": "string", "description": "Alias for `package`" },
                "signer_ref": signer_ref()
            }), &["super_root_address", "root_model_address", "owner_pubkey", "signer_ref"],
            &[&["package"], &["api_schema_json"]])
        }),
        json!({
            "name": "airegistry_get_manifest",
            "description": "Read the full canonical package straight from chain (getApiSchemaChunkCount + getApiSchemaChunk per index, concatenated). Resolve by `manifest_address`, or derive via SuperRoot.getManifestAddress from `super_root_address`+`owner_pubkey`+`root_model_address`. Blockchain-only (no memory). Pass `expected_sha256` to integrity-check the package.",
            "inputSchema": obj(json!({
                "manifest_address": { "type": "string" },
                "super_root_address": { "type": "string" },
                "owner_pubkey": { "type": "string" },
                "root_model_address": { "type": "string" },
                "expected_sha256": { "type": "string" },
                "dapp_id": { "type": "string" }
            }), &[])
        }),
        json!({
            "name": "airegistry_list_marketplace",
            "description": "Discovery by ON-CHAIN EVENTS (blockchain-native, no memory): the event log IS the catalog. Reads the SuperRoot's registered models (RootRegistered) + manifests (ManifestRegistered); `super_root_address` is OPTIONAL — when omitted the service's configured default SuperRoot is used (so a backend indexer need not know the deployment address), and the resolved `super_root_address` is echoed in the response. With `root_model_address` instead, lists that model's token lots (TokenContractRegistered). A real SYNC contract: `events` are oldest-first with stable `message_id`+`lt`+`cursor`; page forward with `first`+`after` (the prior `page_info.end_cursor`), persist `end_cursor` as a checkpoint, and you're caught up when `page_info.has_more` is false. The deduped `root_models`/`manifests`/`token_lots` are a convenience view of the current page.",
            "inputSchema": obj(json!({
                "super_root_address": { "type": "string", "description": "Optional; defaults to the service's configured SuperRoot when omitted" },
                "root_model_address": { "type": "string", "description": "Given instead of super_root_address, lists this model's token lots" },
                "first": { "type": "integer", "description": "Page size (default 50, max 200)" },
                "after": { "type": "string", "description": "Resume after this cursor (a prior page_info.end_cursor) for incremental sync" },
                "dapp_id": { "type": "string" }
            }), &[])
        }),
        json!({
            "name": "airegistry_create_token_lot",
            "description": "Creator: deploy a TokenContract token lot under a RootModel (self-registers → TokenContractRegistered). Persists the token_lot pointer (with optional package_sha256 link).",
            "inputSchema": obj(json!({
                "super_root_address": { "type": "string" },
                "root_model_address": { "type": "string" },
                "seller_pubkey": { "type": "string" },
                "nonce": { "type": "string" },
                "model_name": { "type": "string" },
                "endpoint": { "type": "string" },
                "total_tokens_for_sale": { "type": "string" },
                "tick_size": { "type": "string" },
                "burn_fee_bps": { "type": "integer" },
                "max_reserved_sessions": { "type": "integer" },
                "package_sha256": { "type": "string", "description": "Integrity hash of the on-chain package (stored via airegistry_set_manifest); lets a buyer verify the lot points at the expected package" },
                "signer_ref": signer_ref()
            }), &["root_model_address", "seller_pubkey", "nonce", "model_name", "endpoint", "total_tokens_for_sale", "tick_size", "burn_fee_bps", "max_reserved_sessions", "signer_ref"])
        }),
        json!({
            "name": "airegistry_bill_session",
            "description": "Creator/seller: consumeSession(sessions) — bill delivered usage, moving reserved tokens straight into sellerOwed (no buyer confirmation). The FIRST call after a buyer locks may take up to maxReservedSessions in one batch; every subsequent call must take exactly 1 session. Draining reserved to 0 auto-releases the lot.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "sessions": { "type": "integer" }, "signer_ref": signer_ref() }), &["token_contract_address", "sessions", "signer_ref"])
        }),
        json!({
            "name": "airegistry_replenish",
            "description": "Creator/seller: replenishTokensForSale(amount) — add more tokens to the lot.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "amount": { "type": "string" }, "signer_ref": signer_ref() }), &["token_contract_address", "amount", "signer_ref"])
        }),
        json!({
            "name": "airegistry_set_endpoint",
            "description": "Creator/seller: setEndpoint(endpoint) — update the model API endpoint.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "endpoint": { "type": "string" }, "signer_ref": signer_ref() }), &["token_contract_address", "endpoint", "signer_ref"])
        }),
        json!({
            "name": "airegistry_withdraw_shell",
            "description": "Creator/seller: withdrawShell(amount, recipient) — pull accumulated ECC[2] SHELL revenue.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "amount": { "type": "string" }, "recipient": { "type": "string" }, "signer_ref": signer_ref() }), &["token_contract_address", "amount", "recipient", "signer_ref"])
        }),
        json!({
            "name": "airegistry_destroy_lot",
            "description": "Creator/seller: destroy(payout_address) — selfdestruct a fully-settled lot.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "payout_address": { "type": "string" }, "signer_ref": signer_ref() }), &["token_contract_address", "payout_address", "signer_ref"])
        }),
        json!({
            "name": "airegistry_get_lot",
            "description": "Read a token lot's getCounters/getConfig/getCurrentBuyer/getShellBalance.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "dapp_id": { "type": "string" } }), &["token_contract_address"])
        }),
        // ---- §9.3 consumer ----
        json!({
            "name": "airegistry_resolve_model",
            "description": "Resolve a RootModel + TokenContract address (+ endpoint) for owner/seller/nonce via the on-chain derivation getters.",
            "inputSchema": obj(json!({
                "super_root_address": { "type": "string" },
                "owner_pubkey": { "type": "string" },
                "seller_pubkey": { "type": "string" },
                "nonce": { "type": "string" }
            }), &["super_root_address", "owner_pubkey", "seller_pubkey", "nonce"])
        }),
        json!({
            "name": "airegistry_deploy_buyer",
            "description": "Consumer: deploy a 3-custodian operational wallet (reqConfirms=1) via SwarmRoot — create_keys ×3 then deploy_wallet(req_confirms=1). Persists the oper_wallet pointer.",
            "inputSchema": obj(json!({ "oper_wallet_id": { "type": "string" }, "swarm_root_address": { "type": "string" } }), &["oper_wallet_id", "swarm_root_address"])
        }),
        json!({
            "name": "airegistry_fund_buyer",
            "description": "Consumer: GOVERNED treasury→operational budget top-up. The 2-of-3 treasury submitTransaction QUEUES (cc={2:shell_budget}); a second custodian must confirm_transaction to release it. Rate-limited + policy-gated.",
            "inputSchema": obj(json!({
                "treasury_wallet_id": { "type": "string" },
                "treasury_wallet_address": { "type": "string", "description": "Override the treasury address (requires treasury_dapp_id)" },
                "treasury_dapp_id": { "type": "string", "description": "The treasury's DApp id for getter reads — its SwarmRoot address (deploy_wallet treasury) or its own address (self-originating). Required with treasury_wallet_address." },
                "signer_role": role,
                "oper_wallet_address": { "type": "string" },
                "shell_budget": { "type": "string" }
            }), &["treasury_wallet_id", "signer_role", "oper_wallet_address", "shell_budget"])
        }),
        json!({
            "name": "airegistry_buy_tokens",
            "description": "Consumer: the operational wallet (reqConfirms=1) buys tokens by forwarding shell_amount of ECC[2] SHELL to buyTokens() — executes on the first signature. Rate-limited + delegated-budget policy.",
            "inputSchema": obj(json!({
                "oper_wallet_id": { "type": "string" },
                "oper_wallet_address": { "type": "string" },
                "signer_role": role,
                "token_contract_address": { "type": "string" },
                "shell_amount": { "type": "string" }
            }), &["oper_wallet_id", "signer_role", "token_contract_address", "shell_amount"])
        }),
        json!({
            "name": "airegistry_cancel",
            "description": "Consumer stop-loss: the operational wallet (the buyer) calls cancel() to refund the unconsumed reservedTokens (ECC[2] SHELL) and release the lot lock when the model isn't delivering. Already-billed sessions (sellerOwed) stay with the seller. The refund ALWAYS returns to the operational wallet itself, so the unconsumed delegated budget can't be redirected past the wallet policy.",
            "inputSchema": obj(json!({
                "oper_wallet_id": { "type": "string" },
                "oper_wallet_address": { "type": "string" },
                "signer_role": role,
                "token_contract_address": { "type": "string" }
            }), &["oper_wallet_id", "signer_role", "token_contract_address"])
        }),
        json!({
            "name": "airegistry_get_entitlement",
            "description": "Read the buyer's entitlement on a lot: current_buyer, reserved/consume_calls/seller_owed, endpoint.",
            "inputSchema": obj(json!({ "token_contract_address": { "type": "string" }, "oper_wallet_address": { "type": "string" }, "dapp_id": { "type": "string" } }), &["token_contract_address", "oper_wallet_address"])
        }),
        // ---- §9.4 stateless user-signed payments (Flow A) ----
        json!({
            "name": "airegistry_prepare_user_buy_tokens",
            "description": "Prepare a frontend-safe buyTokens payment intent for the USER'S OWN wallet to sign (Flow A, payload_only). Encodes only the inner TokenContract payload and returns `intent` (incl. `payload_boc_b64`), a structured `wallet_action` { type: shell_transfer_with_body, to, shell_amount (ECC[2] SHELL), native_value_vmshell (gas), body_boc_b64, required_capability: transfer_with_custom_body } describing exactly what the wallet must submit, a `human_summary` (derived from the same inputs), and a chain `preflight` (lot + entitlement). buyTokens() has NO arguments — the amount is the attached ECC[2] value, not a payload field. NO keys, NO memory. `expected_package_sha256` is echoed only — verify via airegistry_get_manifest (the lot has no on-chain package hash).",
            "inputSchema": obj(json!({
                "token_contract_address": { "type": "string" },
                "buyer_wallet_address": { "type": "string" },
                "shell_amount": { "type": "string", "description": "ECC[2] SHELL to attach (uint128)" },
                "native_value_vmshell": { "type": "string", "description": "Native vmshell for gas (default 1e9)" },
                "expected_package_sha256": { "type": "string", "description": "Echoed for your records; not chain-verified here" },
                "client_intent_id": { "type": "string", "description": "Echoed for your idempotency/correlation; not enforced (stateless)" },
                "dapp_id": { "type": "string" }
            }), &["token_contract_address", "buyer_wallet_address", "shell_amount"])
        }),
        json!({
            "name": "airegistry_prepare_user_cancel",
            "description": "Prepare a frontend-safe cancel/refund intent for the user's own wallet to sign (Flow A, payload_only). Encodes `cancel(payoutAddress = buyer_wallet_address)` — `intent.payout_wallet_address` is ALWAYS the buyer, never caller-overridable. Returns `intent`, a structured `wallet_action` { type: shell_transfer_with_body, to, native_value_vmshell (gas, no SHELL), body_boc_b64, required_capability: transfer_with_custom_body }, and a `human_summary`. NO keys, NO memory.",
            "inputSchema": obj(json!({
                "token_contract_address": { "type": "string" },
                "buyer_wallet_address": { "type": "string" },
                "native_value_vmshell": { "type": "string", "description": "Native vmshell for gas (default 1e9)" },
                "client_intent_id": { "type": "string" },
                "dapp_id": { "type": "string" }
            }), &["token_contract_address", "buyer_wallet_address"])
        }),
        json!({
            "name": "airegistry_verify_payment_readiness",
            "description": "Verify whether a buyer wallet is ready to start a package instance, composing chain reads into a single `status` ∈ {verified, not_current_buyer, insufficient_reserved, lot_unavailable, chain_unavailable} with `ready == (status == verified)`, plus `entitlement`, `lot`, and `checked_at`. `minimum_reserved` (default 1) sets the reserved-tokens bar. Pure read (no keys, no memory) — available in --stateless-payments AND --read-only. NO package_hash_mismatch and NO expired/revoked: the lot has no on-chain package hash (verify via airegistry_get_manifest) and expiry/revocation are backend policy, not chain facts.",
            "inputSchema": obj(json!({
                "token_contract_address": { "type": "string" },
                "buyer_wallet_address": { "type": "string" },
                "minimum_reserved": { "type": "string", "description": "Minimum reserved tokens required (uint128, default 1)" },
                "expected_package_sha256": { "type": "string", "description": "Echoed only; verify via airegistry_get_manifest" },
                "dapp_id": { "type": "string" }
            }), &["token_contract_address", "buyer_wallet_address"])
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_schemas_well_formed() {
        let tools = list_airegistry_tools();
        assert_eq!(tools.len(), 23);
        for t in &tools {
            assert!(t["name"].as_str().is_some());
            assert!(t["description"].as_str().is_some());
            assert_eq!(t["inputSchema"]["type"], "object");
            assert!(t["inputSchema"]["required"].is_array());
        }
    }

    #[test]
    fn set_manifest_schema_requires_a_package_field() {
        let tools = list_airegistry_tools();
        let sm = tools
            .iter()
            .find(|t| t["name"] == "airegistry_set_manifest")
            .expect("airegistry_set_manifest tool present");
        let schema = &sm["inputSchema"];
        // The flat `required` list must NOT pretend the package is optional, nor
        // hard-require one specific alias.
        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(!required.contains(&"package"));
        assert!(!required.contains(&"api_schema_json"));
        // `anyOf` must demand at least one of package / api_schema_json, matching
        // the handler (which errors when both are absent).
        let groups: Vec<&str> = schema["anyOf"]
            .as_array()
            .expect("set_manifest must declare anyOf for the package body")
            .iter()
            .filter_map(|g| g["required"].as_array())
            .filter_map(|r| r.first())
            .filter_map(|v| v.as_str())
            .collect();
        assert!(groups.contains(&"package"), "anyOf must allow `package`");
        assert!(
            groups.contains(&"api_schema_json"),
            "anyOf must allow `api_schema_json`"
        );
    }

    #[test]
    fn names_unique_and_expected() {
        let tools = list_airegistry_tools();
        let names: std::collections::HashSet<_> =
            tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names.len(), tools.len(), "duplicate tool name");
        for n in [
            "call_contract",
            "deploy_contract",
            "airegistry_deploy_super_root",
            "airegistry_register_model",
            "airegistry_set_manifest",
            "airegistry_get_manifest",
            "airegistry_list_marketplace",
            "airegistry_create_token_lot",
            "airegistry_bill_session",
            "airegistry_replenish",
            "airegistry_set_endpoint",
            "airegistry_withdraw_shell",
            "airegistry_destroy_lot",
            "airegistry_get_lot",
            "airegistry_resolve_model",
            "airegistry_deploy_buyer",
            "airegistry_fund_buyer",
            "airegistry_buy_tokens",
            "airegistry_cancel",
            "airegistry_get_entitlement",
            "airegistry_prepare_user_buy_tokens",
            "airegistry_prepare_user_cancel",
            "airegistry_verify_payment_readiness",
        ] {
            assert!(names.contains(n), "missing {n}");
        }
    }

    /// Regression: `airegistry_cancel` must NOT expose a `payout_address` override.
    /// The unconsumed delegated budget is always refunded to the operational
    /// wallet; a caller-supplied payout would escape the wallet policy gate
    /// (which only sees dest=token, value=0).
    #[test]
    fn cancel_has_no_payout_override() {
        let tools = list_airegistry_tools();
        let cancel = tools
            .iter()
            .find(|t| t["name"] == "airegistry_cancel")
            .expect("airegistry_cancel");
        let props = &cancel["inputSchema"]["properties"];
        assert!(
            props.get("payout_address").is_none(),
            "airegistry_cancel must not allow a payout override"
        );
    }
}
