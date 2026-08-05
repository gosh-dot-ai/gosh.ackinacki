// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Send external messages to BK node HTTP API.
//! Account state is read from the block stream / REST, NOT mutated here.
//!
//! The current (DApp-aware) BK `/v2/messages` endpoint REQUIRES two routing
//! fields per message — both bare 64-hex, no `0:`/`0x` prefix:
//!   * `account_id` — the message's destination account; the BK rejects the send
//!     if it doesn't equal the destination encoded in the BOC.
//!   * `dapp_id`    — the DApp the destination lives in. The node routes by
//!     `dapp::account`; a wrong dapp_id silently lands the message in the wrong
//!     thread. We read the destination's real dapp_id from `/v2/account` (which
//!     echoes the stored dapp_id regardless of the query arg) rather than guess.

use anyhow::{anyhow, Result};
use serde_json::Value;

/// Strip an optional `0:`/`0x` workchain prefix and lowercase → bare 64-hex.
fn bare_hex(s: &str) -> String {
    s.trim()
        .trim_start_matches("0:")
        .trim_start_matches("0x")
        .to_lowercase()
}

/// Parse the destination account_id (bare 64-hex) out of an external-inbound
/// message BOC. The BK rejects a send whose `account_id` field doesn't equal the
/// message destination (`NotQueuedExtMessage::try_new`), so we derive it from the
/// message itself instead of threading it through every call site.
pub fn dest_account_id_hex(boc_base64: &str) -> Result<String> {
    use base64::Engine;
    use tvm_block::Deserializable;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(boc_base64.trim())
        .map_err(|e| anyhow!("decode message boc: {e}"))?;
    let cell =
        tvm_types::read_single_root_boc(&bytes).map_err(|e| anyhow!("read message boc: {e}"))?;
    let msg =
        tvm_block::Message::construct_from_cell(cell).map_err(|e| anyhow!("parse message: {e}"))?;
    let dst = msg
        .int_dst_account_id()
        .ok_or_else(|| anyhow!("message has no internal destination account"))?;
    Ok(hex::encode(dst.get_bytestring(0)))
}

/// Read an account's real `dapp_id` from the BK REST `/v2/account` endpoint.
///
/// The endpoint echoes the account's *stored* dapp_id regardless of the `dapp_id`
/// query arg (verified live: the Giver at `0:1111…` reports dapp_id all-zeros,
/// i.e. the system DApp, not its own account_id), so we pass the account_id as a
/// throwaway arg. Falls back to the account_id (self-originating default) only
/// when the field is genuinely absent — which a live account never is.
pub async fn fetch_dapp_id(
    http: &reqwest::Client,
    endpoint: &str,
    account_id: &str,
) -> Result<String> {
    let acc = bare_hex(account_id);
    let url = format!(
        "{}/v2/account?account_id={}&dapp_id={}",
        endpoint.trim_end_matches('/'),
        acc,
        acc
    );
    let resp = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let dapp = resp.get("dapp_id").and_then(|v| v.as_str()).map(bare_hex);
    Ok(match dapp {
        Some(d) if d.len() == 64 => d,
        _ => acc,
    })
}

/// The Block Manager answers `/v2/messages` with HTTP 200 even when it *refuses*
/// the message, signalling the refusal only in a top-level `error` object. The
/// common one on a stalled network is `QUEUE_OVERFLOW` ("Message queue is full")
/// — the destination account/thread's queue has filled because the chain isn't
/// draining it (block production halted). Returning `Ok` here used to swallow
/// that, so a halted chain looked like a silent success followed by a long
/// "transaction never landed" timeout. Surface it as an `Err` carrying the
/// `error.code` so the real cause is immediate and callers can branch on it
/// (e.g. probe [`crate::airegistry::getter::AccountReader::chain_liveness`]).
fn check_bm_error(resp: &Value) -> Result<()> {
    // (1) A top-level Block-Manager error object (transport / validation / a
    // synchronous compute abort whose code lives in `error.data`).
    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            let code = err
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("(no message)");
            // Surface the compute exit code EXPLICITLY as `exit_code=<n>` (e.g.
            // RootPN 403 `ERR_INVALID_HISTORY_PROOF`) so a caller can classify the
            // exact code; keep the full object for diagnosis.
            let exit = extract_exit_code(err)
                .map(|c| format!(" exit_code={c}"))
                .unwrap_or_default();
            return Err(anyhow!(
                "block manager rejected message [{code}]:{exit} {message}; error={err}"
            ));
        }
    }
    // (2) A synchronous compute outcome reported under `/result` — the shape the
    // BK `/v2/messages` endpoint returns for an executed message, e.g.
    // `{ "result": { "exit_code": 403, "aborted": true } }`. Without this a
    // nonzero/aborted result was returned as `Ok` and the abort was swallowed.
    // A queue-only ack has neither field and correctly stays `Ok`.
    let result_exit = resp.pointer("/result/exit_code").and_then(|v| v.as_i64());
    let result_aborted = resp.pointer("/result/aborted").and_then(|v| v.as_bool());
    // A nonzero compute exit code (e.g. RootPN 403 `ERR_INVALID_HISTORY_PROOF` /
    // 137 `ERR_INVALID_ZKPROOF`) is the authoritative abort.
    if let Some(code) = result_exit {
        if code != 0 {
            return Err(anyhow!(
                "block manager result reports a nonzero compute exit_code={code} \
                 (aborted={result_aborted:?}): {resp}"
            ));
        }
    }
    // An aborted transaction fails closed on this SHARED path even when the
    // compute exit code is zero (an action-phase abort), because most callers
    // (`ChainClient::call`, `Wallet::submit/confirm`, MCP transaction commands)
    // report success without any effect read. The one benign exception —
    // GiverV3 testnet funding, whose zero-exit action-phase abort still lands the
    // value — is handled locally in `wallet::giver`, only after the funding
    // effect is confirmed downstream. The `exit_code={result_exit:?}` token lets
    // that fixture recognise this exact shape without relaxing the shared path.
    if result_aborted == Some(true) {
        return Err(anyhow!(
            "block manager result reports an aborted transaction (exit_code={result_exit:?}): {resp}"
        ));
    }
    Ok(())
}

/// Recursively find a numeric compute exit code anywhere in a BM error object —
/// any key whose name contains both "exit" and "code" (e.g. `exit_code`,
/// `tvm_exit_code`, `exitCode`) with an integer value. `None` if the BM did not
/// surface a code (a genuinely opaque error → callers must fail closed).
fn extract_exit_code(v: &Value) -> Option<i64> {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let lk = k.to_ascii_lowercase();
                if lk.contains("exit") && lk.contains("code") {
                    if let Some(n) = val.as_i64() {
                        return Some(n);
                    }
                    if let Some(s) = val.as_str() {
                        if let Ok(n) = s.trim().parse::<i64>() {
                            return Some(n);
                        }
                    }
                }
                if let Some(n) = extract_exit_code(val) {
                    return Some(n);
                }
            }
            None
        }
        Value::Array(arr) => arr.iter().find_map(extract_exit_code),
        _ => None,
    }
}

/// Send a signed BOC message to a BK node's HTTP API, resolving the required
/// routing fields automatically: the destination `account_id` is parsed from the
/// BOC and the `dapp_id` is read from the chain. Endpoint is `send_endpoint`.
///
/// Caller should pass a shared `reqwest::Client` to reuse the connection pool /
/// TLS session cache.
pub async fn send_message(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
) -> Result<Value> {
    let account_id = dest_account_id_hex(boc_base64)?;
    let dapp_id = fetch_dapp_id(http, endpoint, &account_id).await?;
    send_message_routed(http, endpoint, boc_base64, &account_id, &dapp_id, None).await
}

/// Like [`send_message`] but with explicit routing fields. Use when the caller
/// already knows the destination/dapp (e.g. avoids the extra `/v2/account`
/// round-trip) or needs a non-default `thread_id`. `account_id` and `dapp_id` are
/// normalised to bare 64-hex; `thread_id` (bare hex) is sent only when `Some`.
pub async fn send_message_routed(
    http: &reqwest::Client,
    endpoint: &str,
    boc_base64: &str,
    account_id: &str,
    dapp_id: &str,
    thread_id: Option<&str>,
) -> Result<Value> {
    let msg_id = uuid::Uuid::new_v4().to_string();
    let mut item = serde_json::json!({
        "id": msg_id,
        "body": boc_base64,
        "account_id": bare_hex(account_id),
        "dapp_id": bare_hex(dapp_id),
    });
    if let Some(t) = thread_id {
        item["thread_id"] = serde_json::json!(bare_hex(t));
    }
    let resp = http
        .post(format!("{}/v2/messages", endpoint.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!([item]))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    check_bm_error(&resp)?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_message_url_format() {
        let endpoint = "https://bk01-testnet.ackinacki.org";
        let url = format!("{}/v2/messages", endpoint.trim_end_matches('/'));
        assert_eq!(url, "https://bk01-testnet.ackinacki.org/v2/messages");
    }

    #[test]
    fn send_message_url_trailing_slash() {
        let endpoint = "https://bk01-testnet.ackinacki.org/";
        let url = format!("{}/v2/messages", endpoint.trim_end_matches('/'));
        assert_eq!(url, "https://bk01-testnet.ackinacki.org/v2/messages");
    }

    #[test]
    fn extract_exit_code_finds_nested_variants() {
        use serde_json::json;
        assert_eq!(
            extract_exit_code(&json!({"code": "TVM_ERROR", "data": {"exit_code": 403}})),
            Some(403)
        );
        // Alternate field naming + string value + deeper nesting.
        assert_eq!(
            extract_exit_code(&json!({"data": {"phase": {"tvm_exit_code": "305"}}})),
            Some(305)
        );
        // No compute exit code anywhere → None (caller fails closed).
        assert_eq!(
            extract_exit_code(&json!({"code": "TVM_ERROR", "message": "compute phase"})),
            None
        );
    }

    #[test]
    fn check_bm_error_surfaces_exit_code_token() {
        use serde_json::json;
        let resp = json!({ "error": { "code": "TVM_ERROR", "message": "compute phase", "data": { "exit_code": 403 } } });
        let err = check_bm_error(&resp).unwrap_err().to_string();
        assert!(err.contains("exit_code=403"), "got: {err}");
    }

    #[test]
    fn check_bm_error_surfaces_queue_overflow() {
        // The real shape the BM returns on a stalled network (HTTP 200 body).
        let resp = serde_json::json!({
            "error": {
                "code": "QUEUE_OVERFLOW",
                "message": "Message queue is full. Please try to send the message later.",
                "data": { "producers": ["shellnet-2.testbk.ackinacki.org"] }
            }
        });
        let err = check_bm_error(&resp).unwrap_err().to_string();
        assert!(err.contains("QUEUE_OVERFLOW"), "got: {err}");
        assert!(err.contains("Message queue is full"), "got: {err}");
    }

    #[test]
    fn check_bm_error_reads_result_compute_outcome() {
        use serde_json::json;
        // 403 ERR_INVALID_HISTORY_PROOF reported under /result (the /v2/messages
        // executed shape) must surface exit_code=403, not pass as Ok.
        let e403 = check_bm_error(&json!({ "result": { "exit_code": 403, "aborted": true } }))
            .unwrap_err()
            .to_string();
        assert!(e403.contains("exit_code=403"), "got: {e403}");
        // 137 ERR_INVALID_ZKPROOF likewise.
        let e137 = check_bm_error(&json!({ "result": { "exit_code": 137, "aborted": true } }))
            .unwrap_err()
            .to_string();
        assert!(e137.contains("exit_code=137"), "got: {e137}");
        // Another nonzero code (e.g. 307) is surfaced too.
        assert!(check_bm_error(&json!({ "result": { "exit_code": 307 } }))
            .unwrap_err()
            .to_string()
            .contains("exit_code=307"));
        // Aborted with NO exit code must fail closed.
        assert!(check_bm_error(&json!({ "result": { "aborted": true } })).is_err());
        // An aborted transaction fails closed on the SHARED path even with a zero
        // compute exit code — ordinary wallet/MCP callers must not read an
        // action-phase-aborted transaction as success. (The benign GiverV3 funding
        // shape is tolerated only locally in `wallet::giver`.)
        let z = check_bm_error(&json!({ "result": { "exit_code": 0, "aborted": true } }))
            .unwrap_err()
            .to_string();
        assert!(
            z.contains("aborted"),
            "zero-exit aborted must fail closed: {z}"
        );
        // A clean executed result passes.
        assert!(check_bm_error(&json!({ "result": { "exit_code": 0, "aborted": false } })).is_ok());
        // A queue-only ack (no error, no /result compute fields) stays Ok.
        assert!(check_bm_error(&json!({ "result": { "message_hash": "0xabc" } })).is_ok());
    }

    #[test]
    fn check_bm_error_passes_success_and_null_error() {
        assert!(check_bm_error(&serde_json::json!({ "result": "ok" })).is_ok());
        assert!(check_bm_error(&serde_json::json!({ "error": null })).is_ok());
        assert!(check_bm_error(&serde_json::json!([])).is_ok());
    }

    #[test]
    fn bare_hex_strips_prefixes_and_lowercases() {
        let raw = "0:ABCD0000000000000000000000000000000000000000000000000000000000EF";
        assert_eq!(
            bare_hex(raw),
            "abcd0000000000000000000000000000000000000000000000000000000000ef"
        );
        assert_eq!(bare_hex("0xFf"), "ff");
        assert_eq!(bare_hex("  00aa  "), "00aa");
    }
}
