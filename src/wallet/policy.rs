// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Wallet policy enforcement.
//!
//! Policies are flat JSON stored in gosh.memory as facts with metadata.
//! This module checks transactions against policy before submission.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Wallet spending policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalletPolicy {
    /// Maximum single transaction amount (nanotoken).
    #[serde(default)]
    pub max_tx_amount: Option<u128>,
    /// Maximum daily spend (nanotoken).
    /// NOTE: Advisory only — not enforced in `check()`. Requires on-chain
    /// or stateful tracking to enforce. Stored for future use.
    #[serde(default)]
    pub daily_limit: Option<u128>,
    /// Allowed destination addresses. Empty = allow all.
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    /// Blocked destination addresses.
    #[serde(default)]
    pub blocked_destinations: Vec<String>,
    /// Policy tier. "frozen" blocks all transactions.
    #[serde(default)]
    pub policy_tier: Option<String>,
}

/// Canonical form for destination comparison: the bare lowercased account id
/// when the string is an (optionally `0:`-prefixed) 64-hex address, else the
/// trimmed lowercased string. So `0:ABCD…` and `0:abcd…` compare equal and a
/// `blocked_destinations`/`allowed_destinations` entry can't be bypassed by an
/// equivalent alternate spelling.
pub fn canon_dest(s: &str) -> String {
    let tail = s.rsplit(':').next().unwrap_or(s).trim().to_lowercase();
    if tail.len() == 64 && tail.chars().all(|c| c.is_ascii_hexdigit()) {
        tail
    } else {
        s.trim().to_lowercase()
    }
}

impl WalletPolicy {
    /// Check if a transaction is allowed by this policy.
    /// Returns Ok(()) if allowed, Err with reason if blocked.
    ///
    /// Destinations are compared by canonical account id on BOTH sides, so an
    /// alternate textual spelling of the same account (e.g. uppercase hex)
    /// cannot bypass a blocked entry or dodge an allow-list.
    pub fn check(&self, dest: &str, value: u128) -> Result<()> {
        // Frozen wallet blocks everything
        if self.policy_tier.as_deref() == Some("frozen") {
            bail!("wallet is frozen");
        }

        // Max transaction amount
        if let Some(max) = self.max_tx_amount {
            if value > max {
                bail!("transaction amount {} exceeds max_tx_amount {}", value, max);
            }
        }

        let dest_c = canon_dest(dest);

        // Blocked destinations
        if self
            .blocked_destinations
            .iter()
            .any(|d| canon_dest(d) == dest_c)
        {
            bail!("destination {dest} is blocked by policy");
        }

        // Allowed destinations (empty = allow all)
        if !self.allowed_destinations.is_empty()
            && !self
                .allowed_destinations
                .iter()
                .any(|d| canon_dest(d) == dest_c)
        {
            bail!("destination {dest} not in allowed_destinations list");
        }

        Ok(())
    }
}

/// Parse a nanotoken amount from JSON without precision loss.
/// Nanotoken amounts are always integers. Rejects non-integer values.
fn parse_nanotoken(v: &serde_json::Value) -> Option<u128> {
    if let Some(n) = v.as_u64() {
        return Some(n as u128);
    }
    if let Some(n) = v.as_i64() {
        if n >= 0 {
            return Some(n as u128);
        }
        return None;
    }
    // No f64 fallback: nanotoken amounts are always integers.
    // Fractional values silently truncate and f64 has precision loss
    // for large integers. Reject anything that isn't u64/i64.
    None
}

/// Find the fact array in a gosh.memory response across its shapes:
///  - direct:      `{"facts": [...]}` / `{"results": [...]}`
///  - nested:      `{"result": {"facts"|"results": [...]}}`
///  - MCP-wrapped: `{"result": {"content": [{"text": "<inner-json>"}]}}` — the
///    shape `MemoryClient::get_wallet_policy` actually produces; the real
///    memory_query JSON is a string under `content[0].text`. We recurse into it.
fn find_facts(resp: &serde_json::Value) -> Option<Vec<serde_json::Value>> {
    for ptr in ["/facts", "/results", "/result/facts", "/result/results"] {
        if let Some(arr) = resp.pointer(ptr).and_then(|v| v.as_array()) {
            return Some(arr.clone());
        }
    }
    // Unwrap the MCP `content[0].text` envelope and recurse into the inner JSON.
    if let Some(text) = resp
        .pointer("/result/content/0/text")
        .or_else(|| resp.pointer("/content/0/text"))
        .and_then(|v| v.as_str())
    {
        if let Ok(inner) = serde_json::from_str::<serde_json::Value>(text) {
            return find_facts(&inner);
        }
    }
    None
}

/// Parse policy from gosh.memory query response.
/// Returns None if no policy found (= no restrictions).
pub fn parse_policy_from_memory(resp: &serde_json::Value) -> Option<WalletPolicy> {
    let facts = find_facts(resp)?;

    // Take the most recent active policy
    let fact = facts.first()?;
    let metadata = fact.get("metadata")?;

    Some(WalletPolicy {
        max_tx_amount: metadata.get("max_tx_amount").and_then(parse_nanotoken),
        daily_limit: metadata.get("daily_limit").and_then(parse_nanotoken),
        allowed_destinations: metadata
            .get("allowed_destinations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        blocked_destinations: metadata
            .get("blocked_destinations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        policy_tier: metadata
            .get("policy_tier")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn default_policy() -> WalletPolicy {
        WalletPolicy::default()
    }

    /// The MCP-wrapped shape `MemoryClient::get_wallet_policy` produces — the
    /// real memory_query JSON is a string under `result.content[0].text`. The
    /// parser must unwrap it; previously it returned None and the gate passed.
    #[test]
    fn parses_policy_from_mcp_wrapped_envelope() {
        let inner = json!({
            "facts": [{ "metadata": {
                "max_tx_amount": 1000,
                "allowed_destinations": ["0:dead"],
                "policy_tier": "frozen"
            }}]
        })
        .to_string();
        let wrapped = json!({ "result": { "content": [{ "type": "text", "text": inner }], "isError": false } });
        let p = parse_policy_from_memory(&wrapped)
            .expect("policy must be parsed from the wrapped envelope");
        assert_eq!(p.max_tx_amount, Some(1000));
        assert_eq!(p.policy_tier.as_deref(), Some("frozen"));
        assert_eq!(p.allowed_destinations, vec!["0:dead".to_string()]);
        // And it actually enforces.
        assert!(p
            .check("0:dead", 1)
            .unwrap_err()
            .to_string()
            .contains("frozen"));
    }

    #[test]
    fn no_facts_in_wrapped_envelope_is_none() {
        let inner = json!({ "results": [] }).to_string();
        let wrapped = json!({ "result": { "content": [{ "text": inner }] } });
        assert!(parse_policy_from_memory(&wrapped).is_none());
    }

    #[test]
    fn no_restrictions_allows_all() {
        let p = default_policy();
        assert!(p.check("0:abc", 1_000_000_000).is_ok());
    }

    #[test]
    fn frozen_blocks_everything() {
        let p = WalletPolicy {
            policy_tier: Some("frozen".into()),
            ..Default::default()
        };
        let err = p.check("0:abc", 100).unwrap_err();
        assert!(err.to_string().contains("frozen"));
    }

    #[test]
    fn max_tx_amount_enforced() {
        let p = WalletPolicy {
            max_tx_amount: Some(1000),
            ..Default::default()
        };
        assert!(p.check("0:abc", 999).is_ok());
        assert!(p.check("0:abc", 1000).is_ok());
        assert!(p.check("0:abc", 1001).is_err());
    }

    #[test]
    fn max_tx_amount_zero_blocks_all() {
        let p = WalletPolicy {
            max_tx_amount: Some(0),
            ..Default::default()
        };
        assert!(p.check("0:abc", 0).is_ok());
        assert!(p.check("0:abc", 1).is_err());
    }

    #[test]
    fn blocked_destination() {
        let p = WalletPolicy {
            blocked_destinations: vec!["0:bad".into()],
            ..Default::default()
        };
        assert!(p.check("0:good", 100).is_ok());
        let err = p.check("0:bad", 100).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn allowed_destinations_whitelist() {
        let p = WalletPolicy {
            allowed_destinations: vec!["0:ok1".into(), "0:ok2".into()],
            ..Default::default()
        };
        assert!(p.check("0:ok1", 100).is_ok());
        assert!(p.check("0:ok2", 100).is_ok());
        let err = p.check("0:other", 100).unwrap_err();
        assert!(err.to_string().contains("not in allowed"));
    }

    #[test]
    fn empty_allowed_destinations_allows_all() {
        let p = WalletPolicy {
            allowed_destinations: vec![],
            ..Default::default()
        };
        assert!(p.check("0:anything", 100).is_ok());
    }

    #[test]
    fn blocked_destination_canonical_not_bypassable_by_spelling() {
        let lower = format!("0:{}", "ab".repeat(32));
        let upper = format!("0:{}", "AB".repeat(32));
        let bare = "ab".repeat(32);
        let p = WalletPolicy {
            blocked_destinations: vec![lower.clone()],
            ..Default::default()
        };
        // Same account, alternate spellings — all blocked.
        assert!(p.check(&lower, 1).is_err());
        assert!(
            p.check(&upper, 1).is_err(),
            "uppercase hex must not bypass a blocked dest"
        );
        assert!(
            p.check(&bare, 1).is_err(),
            "bare (no 0:) hex must not bypass a blocked dest"
        );
        // A genuinely different account is still allowed.
        assert!(p.check(&format!("0:{}", "cd".repeat(32)), 1).is_ok());
    }

    #[test]
    fn allowed_destinations_canonical_match() {
        let p = WalletPolicy {
            allowed_destinations: vec![format!("0:{}", "ab".repeat(32))],
            ..Default::default()
        };
        // Uppercase spelling of the same allow-listed account is accepted.
        assert!(p.check(&format!("0:{}", "AB".repeat(32)), 1).is_ok());
        assert!(p.check(&format!("0:{}", "cd".repeat(32)), 1).is_err());
    }

    #[test]
    fn blocked_takes_priority_over_allowed() {
        let p = WalletPolicy {
            allowed_destinations: vec!["0:addr".into()],
            blocked_destinations: vec!["0:addr".into()],
            ..Default::default()
        };
        // Blocked is checked first
        assert!(p.check("0:addr", 100).is_err());
    }

    #[test]
    fn standard_tier_allows() {
        let p = WalletPolicy {
            policy_tier: Some("standard".into()),
            ..Default::default()
        };
        assert!(p.check("0:abc", 100).is_ok());
    }

    #[test]
    fn multiple_restrictions_combined() {
        let p = WalletPolicy {
            max_tx_amount: Some(1000),
            allowed_destinations: vec!["0:ok".into()],
            blocked_destinations: vec!["0:bad".into()],
            policy_tier: Some("standard".into()),
            ..Default::default()
        };
        assert!(p.check("0:ok", 500).is_ok());
        assert!(p.check("0:ok", 1500).is_err()); // over limit
        assert!(p.check("0:other", 500).is_err()); // not allowed
        assert!(p.check("0:bad", 500).is_err()); // blocked
    }

    #[test]
    fn parse_policy_from_memory_valid() {
        let resp = serde_json::json!({
            "facts": [{
                "fact": "Wallet policy",
                "metadata": {
                    "max_tx_amount": 1000000000,
                    "daily_limit": 5000000000_u64,
                    "allowed_destinations": ["0:abc", "0:def"],
                    "policy_tier": "premium"
                }
            }]
        });
        let policy = parse_policy_from_memory(&resp).unwrap();
        assert_eq!(policy.max_tx_amount, Some(1000000000));
        assert_eq!(policy.daily_limit, Some(5000000000));
        assert_eq!(policy.allowed_destinations.len(), 2);
        assert_eq!(policy.policy_tier.as_deref(), Some("premium"));
    }

    #[test]
    fn parse_policy_from_memory_empty() {
        let resp = serde_json::json!({"facts": []});
        assert!(parse_policy_from_memory(&resp).is_none());
    }

    #[test]
    fn parse_policy_from_memory_no_facts() {
        let resp = serde_json::json!({"error": "something"});
        assert!(parse_policy_from_memory(&resp).is_none());
    }

    #[test]
    fn parse_policy_nested_result() {
        let resp = serde_json::json!({
            "result": {
                "facts": [{
                    "metadata": {
                        "max_tx_amount": 500,
                        "policy_tier": "restricted"
                    }
                }]
            }
        });
        let policy = parse_policy_from_memory(&resp).unwrap();
        assert_eq!(policy.max_tx_amount, Some(500));
        assert_eq!(policy.policy_tier.as_deref(), Some("restricted"));
    }

    #[test]
    fn serde_roundtrip() {
        let p = WalletPolicy {
            max_tx_amount: Some(1000),
            daily_limit: Some(5000),
            allowed_destinations: vec!["0:a".into()],
            blocked_destinations: vec!["0:b".into()],
            policy_tier: Some("premium".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let restored: WalletPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_tx_amount, p.max_tx_amount);
        assert_eq!(restored.policy_tier, p.policy_tier);
    }
}
