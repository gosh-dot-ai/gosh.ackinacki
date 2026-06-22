// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Filter rules: which messages from the block stream to keep.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Which message types to match.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MsgTypeFilter {
    Internal,
    ExtIn,
    ExtOut,
}

/// A single filter rule. A message matches if it satisfies ALL non-None fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FilterRule {
    /// Match messages where src OR dst is in this set.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub addresses: HashSet<String>,

    /// Match only these message types.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub msg_types: HashSet<MsgTypeFilter>,

    /// Match messages where ABI method name is in this set.
    /// Requires ABI to be loaded for the destination contract.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub method_names: HashSet<String>,
}

/// Complete filter configuration: a message passes if it matches ANY rule.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FilterConfig {
    pub rules: Vec<FilterRule>,
}

impl FilterRule {
    /// Check if a message matches this rule.
    /// `src` / `dst` are formatted as "workchain:hex_address" (e.g. "0:abc...").
    /// `msg_type` is the message type.
    /// `method_name` is the decoded ABI method (None if not decoded).
    pub fn matches(
        &self,
        src: Option<&str>,
        dst: Option<&str>,
        msg_type: &MsgTypeFilter,
        method_name: Option<&str>,
    ) -> bool {
        // Address filter: at least one of src/dst must be in the set
        if !self.addresses.is_empty() {
            let src_match = src.is_some_and(|s| self.addresses.contains(s));
            let dst_match = dst.is_some_and(|d| self.addresses.contains(d));
            if !src_match && !dst_match {
                return false;
            }
        }

        // Message type filter
        if !self.msg_types.is_empty() && !self.msg_types.contains(msg_type) {
            return false;
        }

        // Method name filter
        if !self.method_names.is_empty() {
            match method_name {
                Some(name) if self.method_names.contains(name) => {}
                _ => return false,
            }
        }

        true
    }
}

impl FilterConfig {
    /// A message passes if it matches ANY rule. Empty rules = reject all.
    pub fn matches(
        &self,
        src: Option<&str>,
        dst: Option<&str>,
        msg_type: &MsgTypeFilter,
        method_name: Option<&str>,
    ) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        self.rules
            .iter()
            .any(|r| r.matches(src, dst, msg_type, method_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_rejects_all() {
        let cfg = FilterConfig::default();
        assert!(!cfg.matches(Some("0:abc"), Some("0:def"), &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn address_filter() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:abc".into()]),
            ..Default::default()
        };
        assert!(rule.matches(Some("0:abc"), Some("0:def"), &MsgTypeFilter::Internal, None));
        assert!(rule.matches(Some("0:def"), Some("0:abc"), &MsgTypeFilter::Internal, None));
        assert!(!rule.matches(Some("0:def"), Some("0:ghi"), &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn msg_type_filter() {
        let rule = FilterRule {
            msg_types: HashSet::from([MsgTypeFilter::ExtOut]),
            ..Default::default()
        };
        assert!(!rule.matches(Some("0:a"), Some("0:b"), &MsgTypeFilter::Internal, None));
        assert!(rule.matches(Some("0:a"), Some("0:b"), &MsgTypeFilter::ExtOut, None));
    }

    #[test]
    fn method_filter() {
        let rule = FilterRule {
            method_names: HashSet::from(["transfer".into()]),
            ..Default::default()
        };
        assert!(rule.matches(None, None, &MsgTypeFilter::Internal, Some("transfer")));
        assert!(!rule.matches(None, None, &MsgTypeFilter::Internal, Some("deploy")));
        assert!(!rule.matches(None, None, &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn any_rule_matches() {
        let cfg = FilterConfig {
            rules: vec![
                FilterRule {
                    addresses: HashSet::from(["0:abc".into()]),
                    ..Default::default()
                },
                FilterRule {
                    msg_types: HashSet::from([MsgTypeFilter::ExtOut]),
                    ..Default::default()
                },
            ],
        };
        // Matches first rule (address)
        assert!(cfg.matches(Some("0:abc"), None, &MsgTypeFilter::Internal, None));
        // Matches second rule (ext_out)
        assert!(cfg.matches(Some("0:xyz"), None, &MsgTypeFilter::ExtOut, None));
        // Matches neither
        assert!(!cfg.matches(Some("0:xyz"), None, &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn combined_address_msg_type_method_filter() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:abc".into()]),
            msg_types: HashSet::from([MsgTypeFilter::Internal]),
            method_names: HashSet::from(["transfer".into()]),
        };
        // All three match
        assert!(rule.matches(
            Some("0:abc"),
            Some("0:def"),
            &MsgTypeFilter::Internal,
            Some("transfer"),
        ));
        // Address misses
        assert!(!rule.matches(
            Some("0:xyz"),
            Some("0:def"),
            &MsgTypeFilter::Internal,
            Some("transfer"),
        ));
        // Msg type misses
        assert!(!rule.matches(
            Some("0:abc"),
            Some("0:def"),
            &MsgTypeFilter::ExtIn,
            Some("transfer"),
        ));
        // Method misses
        assert!(!rule.matches(
            Some("0:abc"),
            Some("0:def"),
            &MsgTypeFilter::Internal,
            Some("deploy"),
        ));
    }

    #[test]
    fn all_fields_empty_passes_everything() {
        let rule = FilterRule::default();
        assert!(rule.matches(
            Some("0:a"),
            Some("0:b"),
            &MsgTypeFilter::Internal,
            Some("x")
        ));
        assert!(rule.matches(None, None, &MsgTypeFilter::ExtIn, None));
        assert!(rule.matches(None, None, &MsgTypeFilter::ExtOut, Some("event")));
    }

    #[test]
    fn multiple_rules_first_match_wins() {
        // First rule: address filter. Second rule: msg type filter.
        // A message matching only the second rule still passes.
        let cfg = FilterConfig {
            rules: vec![
                FilterRule {
                    addresses: HashSet::from(["0:first".into()]),
                    ..Default::default()
                },
                FilterRule {
                    addresses: HashSet::from(["0:second".into()]),
                    ..Default::default()
                },
            ],
        };
        assert!(cfg.matches(Some("0:first"), None, &MsgTypeFilter::Internal, None));
        assert!(cfg.matches(Some("0:second"), None, &MsgTypeFilter::Internal, None));
        assert!(!cfg.matches(Some("0:third"), None, &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn address_matches_src_only() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:target".into()]),
            ..Default::default()
        };
        // src matches, dst is different
        assert!(rule.matches(
            Some("0:target"),
            Some("0:other"),
            &MsgTypeFilter::Internal,
            None
        ));
        // src matches, dst is None
        assert!(rule.matches(Some("0:target"), None, &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn address_matches_dst_only() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:target".into()]),
            ..Default::default()
        };
        // dst matches, src is different
        assert!(rule.matches(
            Some("0:other"),
            Some("0:target"),
            &MsgTypeFilter::Internal,
            None
        ));
        // dst matches, src is None
        assert!(rule.matches(None, Some("0:target"), &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn address_filter_both_none_fails() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:target".into()]),
            ..Default::default()
        };
        assert!(!rule.matches(None, None, &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn serde_roundtrip_filter_config() {
        let cfg = FilterConfig {
            rules: vec![
                FilterRule {
                    addresses: HashSet::from(["0:abc".into(), "0:def".into()]),
                    msg_types: HashSet::from([MsgTypeFilter::Internal, MsgTypeFilter::ExtOut]),
                    method_names: HashSet::from(["transfer".into()]),
                },
                FilterRule::default(),
            ],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: FilterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.rules.len(), 2);
        assert_eq!(restored.rules[0].addresses, cfg.rules[0].addresses);
        assert_eq!(restored.rules[0].msg_types, cfg.rules[0].msg_types);
        assert_eq!(restored.rules[0].method_names, cfg.rules[0].method_names);
    }

    #[test]
    fn serde_roundtrip_filter_rule() {
        let rule = FilterRule {
            addresses: HashSet::from(["0:abc".into()]),
            msg_types: HashSet::from([MsgTypeFilter::ExtIn]),
            method_names: HashSet::new(),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let restored: FilterRule = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.addresses, rule.addresses);
        assert_eq!(restored.msg_types, rule.msg_types);
        assert!(restored.method_names.is_empty());
    }

    #[test]
    fn msg_type_filter_serde_rename() {
        let json = r#""internal""#;
        let val: MsgTypeFilter = serde_json::from_str(json).unwrap();
        assert_eq!(val, MsgTypeFilter::Internal);

        let json = r#""ext_in""#;
        let val: MsgTypeFilter = serde_json::from_str(json).unwrap();
        assert_eq!(val, MsgTypeFilter::ExtIn);

        let json = r#""ext_out""#;
        let val: MsgTypeFilter = serde_json::from_str(json).unwrap();
        assert_eq!(val, MsgTypeFilter::ExtOut);
    }

    #[test]
    fn method_filter_none_method_fails() {
        let rule = FilterRule {
            method_names: HashSet::from(["transfer".into()]),
            ..Default::default()
        };
        // method_name is None => fails because method_names is not empty
        assert!(!rule.matches(Some("0:a"), Some("0:b"), &MsgTypeFilter::Internal, None));
    }

    #[test]
    fn config_with_no_rules_passes_none_addrs() {
        let cfg = FilterConfig::default();
        assert!(!cfg.matches(None, None, &MsgTypeFilter::Internal, None));
    }
}
