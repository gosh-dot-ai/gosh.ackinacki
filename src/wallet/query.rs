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
    let err = match resp.get("error") {
        Some(e) if !e.is_null() => e,
        _ => return Ok(()),
    };
    let code = err
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let message = err
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("(no message)");
    Err(anyhow!(
        "block manager rejected message [{code}]: {message}"
    ))
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
