// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Stable value types for the SDK surface: a blockchain [`Address`], an ed25519
//! [`Pubkey`], and an ed25519 [`Signature`].
//!
//! These are thin, validated newtypes over the bare-hex strings the lower
//! layers already pass around — they add type safety at the API boundary
//! without changing any wire format. Each parses the forms seen in the wild and
//! stores one canonical representation.

use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Result};

/// Lowercase `s` and return it iff it is exactly `n_bytes * 2` hex digits.
fn normalize_hex(s: &str, n_bytes: usize, what: &str) -> Result<String> {
    let h = s.trim().to_lowercase();
    let want = n_bytes * 2;
    if h.len() != want || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid {what}: expected {want} hex digits, got {s:?}");
    }
    Ok(h)
}

/// A workchain-0 contract account address. Stored canonically as **bare 64-hex**
/// (lowercase, no workchain prefix) — the form the Block Manager GraphQL /
/// `/v2/*` endpoints want. [`Display`] renders `0:<hex>`.
///
/// [`Address::parse`] accepts `0:<hex>`, `0x<hex>`, or bare `<hex>`. Non-zero
/// workchains are rejected instead of being silently rewritten to workchain 0.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(String);

impl Address {
    /// Parse from any accepted form into the canonical bare 64-hex.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let stripped = if let Some((workchain, address)) = s.split_once(':') {
            if workchain != "0" {
                bail!("unsupported address workchain {workchain:?}; sdk Address supports only workchain 0");
            }
            address
        } else {
            s.strip_prefix("0x").unwrap_or(s)
        };
        Ok(Self(normalize_hex(stripped, 32, "address")?))
    }

    /// Bare 64-hex, no prefix (the form GraphQL / `/v2/messages` routing want).
    pub fn bare(&self) -> &str {
        &self.0
    }

    /// `0:<hex>` workchain-qualified form.
    pub fn with_workchain(&self) -> String {
        format!("0:{}", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0:{}", self.0)
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// An ed25519 public key (32 bytes) — the signing identity for blockchain
/// messages. Stored as bare 64-hex (lowercase); [`Display`] renders `0x<hex>`,
/// the form `encode_message`'s init data (`_pubkey`) and headers expect.
///
/// [`Pubkey::parse`] accepts `0x<hex>` or bare `<hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pubkey(String);

impl Pubkey {
    /// Parse from `0x<hex>` or bare `<hex>` into the canonical bare 64-hex.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        Ok(Self(normalize_hex(stripped, 32, "pubkey")?))
    }

    /// Bare 64-hex, no prefix.
    pub fn hex(&self) -> &str {
        &self.0
    }

    /// `0x<hex>` form (init data / ABI header).
    pub fn with_0x(&self) -> String {
        format!("0x{}", self.0)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.0)
    }
}

impl FromStr for Pubkey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// An ed25519 signature (64 bytes), stored and rendered as bare 128-hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature(String);

impl Signature {
    /// Parse from `0x<hex>` or bare `<hex>` into the canonical bare 128-hex.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        Ok(Self(normalize_hex(stripped, 64, "signature")?))
    }

    /// Bare 128-hex, no prefix.
    pub fn hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Signature {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c";
    const HEX128: &str = "128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c128a5586045a9a3c300f99ef958d5536ab5d4fbaad6e3726321e87a071d4834c";

    #[test]
    fn address_parses_all_forms_to_bare() {
        let want = HEX64;
        for input in [
            HEX64.to_string(),
            format!("0:{HEX64}"),
            format!("0x{HEX64}"),
            format!("  0:{}  ", HEX64.to_uppercase()),
        ] {
            let a = Address::parse(&input).unwrap();
            assert_eq!(a.bare(), want, "input {input:?}");
            assert_eq!(a.with_workchain(), format!("0:{want}"));
            assert_eq!(a.to_string(), format!("0:{want}"));
        }
    }

    #[test]
    fn address_rejects_bad() {
        assert!(Address::parse("0:tooshort").is_err());
        assert!(Address::parse("").is_err());
        assert!(Address::parse(&format!("0:zz{}", &HEX64[2..])).is_err());
        assert!(Address::parse(&format!("-1:{HEX64}")).is_err());
        assert!(Address::parse(&format!("1:{HEX64}")).is_err());
        // 63 hex digits — one short.
        assert!(Address::parse(&HEX64[1..]).is_err());
    }

    #[test]
    fn address_roundtrips_via_fromstr() {
        let a: Address = format!("0:{HEX64}").parse().unwrap();
        let b = Address::parse(&a.to_string()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn pubkey_parses_and_renders_with_0x() {
        let p = Pubkey::parse(&format!("0x{HEX64}")).unwrap();
        assert_eq!(p.hex(), HEX64);
        assert_eq!(p.with_0x(), format!("0x{HEX64}"));
        assert_eq!(p.to_string(), format!("0x{HEX64}"));
        // bare also accepted, uppercase normalised
        assert_eq!(Pubkey::parse(&HEX64.to_uppercase()).unwrap().hex(), HEX64);
    }

    #[test]
    fn pubkey_rejects_wrong_length() {
        assert!(Pubkey::parse(HEX128).is_err());
        assert!(Pubkey::parse("0x").is_err());
    }

    #[test]
    fn signature_is_128_hex() {
        let s = Signature::parse(HEX128).unwrap();
        assert_eq!(s.hex(), HEX128);
        assert_eq!(s.to_string(), HEX128);
        assert_eq!(
            Signature::parse(&format!("0x{HEX128}")).unwrap().hex(),
            HEX128
        );
        // a 64-hex pubkey is not a valid signature
        assert!(Signature::parse(HEX64).is_err());
    }
}
