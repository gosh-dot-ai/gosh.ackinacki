// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! DEX proof helpers: token taxonomy, nominal denominations, and u256 helpers.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::private_note::halo2::live::Halo2Proof;

pub const CURRENCY_ID_SHELL: u32 = 2;
pub const ECC_SHELL_DEPOSIT_RAW: u64 = 100_000_000_000;

/// Deposit token types supported by `onboard_user_shellnet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Nackl,
    Shell,
    Usdc,
}

impl TokenType {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "nackl" | "1" => Ok(Self::Nackl),
            "shell" | "2" => Ok(Self::Shell),
            "usdc" | "3" => Ok(Self::Usdc),
            other => bail!("unknown token-type `{other}` (use nackl|shell|usdc)"),
        }
    }

    pub fn id(self) -> u32 {
        match self {
            Self::Nackl => 1,
            Self::Shell => 2,
            Self::Usdc => 3,
        }
    }

    pub fn decimals(self) -> u64 {
        match self {
            Self::Usdc => 1_000_000,
            _ => 1_000_000_000,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Nackl => "NACKL",
            Self::Shell => "SHELL",
            Self::Usdc => "USDC",
        }
    }
}

/// PrivateNote deposit nominal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Nominal {
    N100,
    N1000,
    N10000,
}

impl Nominal {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "n100" | "100" => Ok(Self::N100),
            "n1000" | "1000" => Ok(Self::N1000),
            "n10000" | "10000" => Ok(Self::N10000),
            other => bail!("unknown nominal `{other}` (use N100|N1000|N10000)"),
        }
    }

    pub fn count(self) -> u64 {
        match self {
            Self::N100 => 100,
            Self::N1000 => 1_000,
            Self::N10000 => 10_000,
        }
    }

    pub fn raw_value(self, token_type: TokenType) -> u64 {
        self.count() * token_type.decimals()
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::N100 => "N100",
            Self::N1000 => "N1000",
            Self::N10000 => "N10000",
        }
    }
}

pub fn random_secret_key() -> String {
    let seed = format!(
        "{}:{}:gosh-ackinacki-private-note",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos(),
    );
    let mut bytes = Sha256::digest(seed.as_bytes()).to_vec();
    // Last byte < 0x30 keeps the 32-byte little-endian value < BN254 Fr modulus.
    bytes[31] %= 0x30;
    hex::encode(bytes)
}

pub fn hex_u256_to_dec(hex: &str) -> String {
    let hex = strip_0x(hex);
    num_bigint::BigUint::parse_bytes(hex.as_bytes(), 16)
        .expect("valid hex uint256")
        .to_string()
}

pub fn pubkey_to_dec(pubkey: &str) -> String {
    hex_u256_to_dec(pubkey)
}

pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

pub fn parse_u256(value: &str) -> Result<num_bigint::BigUint> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return num_bigint::BigUint::parse_bytes(hex.as_bytes(), 16)
            .ok_or_else(|| anyhow!("invalid hex uint256 `{value}`"));
    }
    num_bigint::BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| anyhow!("invalid decimal uint256 `{value}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_compatible_parse_labels_and_raw_values() {
        assert_eq!(TokenType::parse("shell").unwrap().id(), 2);
        assert_eq!(TokenType::parse("3").unwrap().label(), "USDC");
        assert_eq!(
            Nominal::parse("N100").unwrap().raw_value(TokenType::Nackl),
            100_000_000_000
        );
        assert_eq!(Nominal::parse("10000").unwrap().label(), "N10000");
    }

    #[test]
    fn bad_cli_values_fail_closed() {
        assert!(TokenType::parse("btc").is_err());
        assert!(Nominal::parse("42").is_err());
    }
}
