// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! airegistry on-chain error codes (§11) → readable messages.
//!
//! The contracts revert with `ERR_*` exit codes (301–317, from
//! `airegistry/modifiers/errors.sol`). When a send response surfaces a non-zero
//! `exit_code`, [`map_exit_code`] turns it into a caller-facing message.

/// Human-readable message for an airegistry `ERR_*` exit code, if known.
pub fn err_message(code: i64) -> Option<&'static str> {
    Some(match code {
        301 => "ERR_NOT_OWNER: caller is not the owner",
        302 => "ERR_INVALID_SENDER: message sender is not permitted",
        303 => "ERR_ZERO_AMOUNT: amount must be greater than zero",
        304 => "ERR_ALREADY_REGISTERED: already registered",
        305 => "ERR_NOT_INITIALIZED: contract not initialized",
        306 => "ERR_INSUFFICIENT_TOKENS: not enough tokens available for sale",
        307 => "ERR_CONTRACT_LOCKED: the lot is locked to another buyer",
        308 => "ERR_NOT_RESERVED: no matching reservation",
        309 => "ERR_RESERVATION_OVERFLOW: reservation overflow",
        310 => "ERR_NOT_EMPTY: outstanding reserved tokens remain",
        311 => "ERR_NO_SHELL: no ECC[2] SHELL attached to the call",
        312 => "ERR_BAD_FEE_BPS: burnFeeBps must be < 10000",
        313 => "ERR_BAD_PARAM: invalid parameter",
        314 => "ERR_OVERFLOW: arithmetic overflow",
        315 => "ERR_FIRST_BATCH_LIMIT: first consumeSession exceeds maxReservedSessions",
        316 => "ERR_BAD_CODE_HASH: supplied child code hash does not match the locked hash",
        317 => "ERR_SINGLE_SESSION_REQUIRED: after the first batch, consumeSession must take exactly one session",
        _ => return None,
    })
}

/// Inspect a BK send response for a non-zero compute `exit_code`. Returns an
/// `Err` with the mapped airegistry message (or the raw code) when the
/// transaction aborted, `Ok(())` otherwise. The response shape mirrors
/// `wallet::query::send_message` (`/result/exit_code`, `/result/aborted`).
pub fn check_send_response(resp: &serde_json::Value) -> anyhow::Result<()> {
    let exit = resp.pointer("/result/exit_code").and_then(|v| v.as_i64());
    let aborted = resp.pointer("/result/aborted").and_then(|v| v.as_bool());
    if let Some(code) = exit {
        if code != 0 {
            return Err(map_exit_code(code));
        }
    }
    if aborted == Some(true) {
        return Err(anyhow::anyhow!("transaction aborted on-chain: {resp}"));
    }
    Ok(())
}

/// Turn a non-zero exit code into an error, mapping known airegistry codes.
pub fn map_exit_code(code: i64) -> anyhow::Error {
    match err_message(code) {
        Some(msg) => anyhow::anyhow!("on-chain revert (exit_code {code}): {msg}"),
        None => anyhow::anyhow!("on-chain revert (exit_code {code})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn known_codes_map() {
        assert!(err_message(306).unwrap().contains("INSUFFICIENT_TOKENS"));
        assert!(err_message(307).unwrap().contains("LOCKED"));
        assert!(err_message(315).unwrap().contains("FIRST_BATCH_LIMIT"));
        assert!(err_message(316).unwrap().contains("BAD_CODE_HASH"));
        assert!(err_message(317)
            .unwrap()
            .contains("SINGLE_SESSION_REQUIRED"));
        assert!(err_message(999).is_none());
    }

    #[test]
    fn check_send_response_flags_nonzero_exit() {
        let ok = json!({ "result": { "exit_code": 0, "aborted": false } });
        assert!(check_send_response(&ok).is_ok());
        let locked = json!({ "result": { "exit_code": 307 } });
        let e = check_send_response(&locked).unwrap_err().to_string();
        assert!(e.contains("307") && e.contains("LOCKED"), "{e}");
        let aborted = json!({ "result": { "aborted": true } });
        assert!(check_send_response(&aborted).is_err());
    }

    #[test]
    fn check_send_response_passes_when_no_exit_info() {
        // Many BK responses carry producer/feedback info but no exit_code; the
        // mutation's effect is asserted separately (state read). Don't fail here.
        assert!(check_send_response(&json!({ "result": { "producers": [] } })).is_ok());
    }
}
