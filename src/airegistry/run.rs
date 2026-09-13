// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Local getter execution: run an ABI getter against a fetched account BOC.
//!
//! Getters (`getDetails`, `getRootModelAddress`, `getApiSchema`, …) are ABI
//! functions, so we run them **locally** with `tvm_client::run_tvm` — execute
//! the contract code over the account state with an unsigned external getter
//! message, then decode the returned ext-out message. No transaction is sent,
//! no signature is needed (getters `tvm.accept` with no `require(msg.pubkey…)`).
//!
//! Transport: the account BOC comes from [`super::getter::AccountReader`]
//! (shellnet GraphQL). The `tvm_client` runtime is local-only (no network
//! endpoints), so `run_tvm`/`encode_message` never touch the wire.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tvm_client::abi::{encode_message, Abi, CallSet, ParamsOfEncodeMessage, Signer};
use tvm_client::tvm::{run_tvm, ParamsOfRunTvm};
use tvm_client::{ClientConfig, ClientContext};

use super::getter::{AccountOrigin, AccountReader};
use crate::config::AiRegistryConfig;

/// Runs ABI getters locally. Holds a network-less `tvm_client` context.
#[derive(Clone)]
pub struct GetterRunner {
    ctx: Arc<ClientContext>,
}

impl GetterRunner {
    pub fn new() -> Result<Self> {
        // Default config has no network endpoints ⇒ a local-only context; run_tvm
        // and encode_message execute entirely in-process.
        let ctx = ClientContext::new(ClientConfig::default())
            .map_err(|e| anyhow!("create local tvm client context: {e}"))?;
        Ok(Self { ctx: Arc::new(ctx) })
    }

    /// Run getter `method(input)` on `address` against `account_boc_b64`,
    /// returning the decoded output JSON object (ABI return params).
    pub async fn run_getter(
        &self,
        abi_json: &str,
        address: &str,
        account_boc_b64: &str,
        method: &str,
        input: Value,
    ) -> Result<Value> {
        let abi = Abi::Json(abi_json.to_string());

        let encoded = encode_message(
            self.ctx.clone(),
            ParamsOfEncodeMessage {
                abi: abi.clone(),
                address: Some(address.to_string()),
                deploy_set: None,
                call_set: Some(CallSet {
                    function_name: method.to_string(),
                    header: None,
                    input: Some(input),
                }),
                signer: Signer::None,
                processing_try_index: None,
                signature_id: None,
            },
        )
        .await
        .map_err(|e| anyhow!("encode getter message {method}: {e}"))?;

        let result = run_tvm(
            self.ctx.clone(),
            ParamsOfRunTvm {
                message: encoded.message,
                account: account_boc_b64.to_string(),
                execution_options: None,
                abi: Some(abi),
                boc_cache: None,
                return_updated_account: Some(false),
            },
        )
        .await
        .map_err(|e| anyhow!("run_tvm getter {method}: {e}"))?;

        let decoded = result
            .decoded
            .ok_or_else(|| anyhow!("getter {method}: no decoded output"))?;
        decoded
            .out_messages
            .into_iter()
            .flatten()
            .find_map(|m| m.value)
            .ok_or_else(|| anyhow!("getter {method}: returned no output message"))
    }
}

/// Fetch an account and run a getter on it in one call. `Ok(None)` if the
/// account is not found / not active.
#[allow(clippy::too_many_arguments)]
pub async fn read_getter(
    reader: &AccountReader,
    runner: &GetterRunner,
    cfg: &AiRegistryConfig,
    abi_json: &str,
    address: &str,
    origin: &AccountOrigin,
    method: &str,
    input: Value,
) -> Result<Option<Value>> {
    let snapshot = match reader.fetch(cfg, address, origin).await? {
        Some(s) if s.is_active() => s,
        _ => return Ok(None),
    };
    let boc = snapshot
        .boc
        .ok_or_else(|| anyhow!("account {address} active but returned no boc"))?;
    let out = runner
        .run_getter(abi_json, address, &boc, method, input)
        .await?;
    Ok(Some(out))
}

/// Convenience: a getter with no input parameters.
pub fn no_args() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airegistry::abi::GIVER_ABI_JSON;

    #[test]
    fn runner_constructs() {
        GetterRunner::new().expect("local tvm context");
    }

    /// Live end-to-end getter run against shellnet: fetch the Giver BOC and run
    /// its `getMessages()` getter locally, asserting we decode a `messages`
    /// array. This validates the full read path (fetch → run_tvm → decode)
    /// against a real on-chain account — not just airegistry, but the same
    /// machinery used for getDetails/getRootModelAddress/… in Phase 2.
    /// Run: `GOSH_AIREGISTRY_LIVE=1 cargo test --lib airegistry::run::tests::live`.
    #[tokio::test]
    async fn live_run_giver_getmessages() {
        if std::env::var("GOSH_AIREGISTRY_LIVE").is_err() {
            eprintln!("live_run_giver_getmessages: SKIPPED (set GOSH_AIREGISTRY_LIVE=1)");
            return;
        }
        let cfg = AiRegistryConfig::shellnet();
        let reader = AccountReader::new(reqwest::Client::new(), "https://shellnet.ackinacki.org");
        let runner = GetterRunner::new().unwrap();
        let giver = cfg.giver_address.clone().unwrap();

        let out = read_getter(
            &reader,
            &runner,
            &cfg,
            GIVER_ABI_JSON,
            &giver,
            &AccountOrigin::SelfOriginating,
            "getMessages",
            no_args(),
        )
        .await
        .expect("read_getter")
        .expect("giver active");

        eprintln!("LIVE getMessages output: {out}");
        assert!(
            out.get("messages").is_some(),
            "expected a 'messages' field in getMessages output, got {out}"
        );
    }
}
