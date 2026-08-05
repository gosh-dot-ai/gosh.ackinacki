// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! DEX proof helpers: token taxonomy, nominal denominations, and u256 helpers.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

pub use crate::private_note::halo2::live::Halo2Proof;

pub const CURRENCY_ID_SHELL: u32 = 2;
pub const ECC_SHELL_DEPOSIT_RAW: u64 = 100_000_000_000;

/// RootPN `GAS_DEPOSIT` (`contracts/dex/modifiers/modifiers.sol`, shellnet 4.0.33):
/// the extra SHELL a **deposit** voucher must attach on top of the nominal.
/// `RootPN.generateVoucher` computes `nominal = attached - GAS_DEPOSIT` on the
/// non-fee leg (aborting `ERR_BELOW_GAS_DEPOSIT` / 408 if `attached < GAS_DEPOSIT`);
/// the fee/gas leg (`isFee == true`) is deducted nothing.
pub const ROOT_PN_GAS_DEPOSIT_RAW: u64 = 250_000_000_000;

/// The raw currency amount a voucher's wallet call must ATTACH (`cc` value):
/// the deposit leg (`is_fee == false`) wires `nominal + GAS_DEPOSIT`; the gas leg
/// (`is_fee == true`) wires exactly `raw_value`. The proof / `deployPrivateNote`
/// still use the post-deduction nominal (what `VoucherGenerated` emits), NOT this
/// wired amount. Mirrors dexdo's `note_deploy_voucher_wire_raw`.
pub fn voucher_wire_raw(is_fee: bool, raw_value: u64) -> u128 {
    if is_fee {
        u128::from(raw_value)
    } else {
        u128::from(raw_value) + u128::from(ROOT_PN_GAS_DEPOSIT_RAW)
    }
}

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

/// Sample a fresh voucher secret `sk_u` (32-byte BN254 `Fr`, little-endian hex)
/// from the OS CSPRNG. This is the SOLE secret protecting a voucher
/// (`skUCommit = poseidon([sk_u, 0])`), so it MUST be unpredictable — it is
/// never derived from low-entropy inputs like the PID or wall clock.
pub fn random_secret_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Reduce into the BN254 Fr range: the modulus' most-significant (LE byte 31)
    // limb is 0x30, so forcing byte[31] < 0x30 keeps the value < modulus while
    // preserving ~248 bits of entropy.
    bytes[31] %= 0x30;
    hex::encode(bytes)
}

pub fn hex_u256_to_dec(hex: &str) -> Result<String> {
    let stripped = strip_0x(hex);
    Ok(num_bigint::BigUint::parse_bytes(stripped.as_bytes(), 16)
        .ok_or_else(|| anyhow!("invalid hex uint256 `{hex}`"))?
        .to_string())
}

pub fn pubkey_to_dec(pubkey: &str) -> Result<String> {
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
