// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Embedded airegistry + Giver artifacts, with load-time code-hash verification.
//!
//! The contracts are **code-hash-locked**: `SuperRoot`/`RootModel` reject any
//! caller-supplied child code whose `tvm.hash` does not match a constant baked
//! into their bytecode. We mirror that off-chain — the embedded TVCs MUST hash
//! to the values in [`crate::config::AiRegistryConfig`], or we fail fast (a
//! drifted vendored artifact is a hard error, not a silent wrong-address bug).
//!
//! Artifacts are a **mutable snapshot** vendored under `contracts/airegistry/`
//! and `contracts/giver/`; bump them (and the config hashes) when upstream
//! airegistry moves. Source: `gosh-sh/acki-nacki@86d1dec3` (airegistry) and
//! `@poseidon_dex` (GiverV3).

use anyhow::{anyhow, bail, Context, Result};
use tvm_block::{Deserializable, StateInit};

// ---- embedded ABIs ----
pub const SUPER_ROOT_ABI_JSON: &str = include_str!("../../contracts/airegistry/SuperRoot.abi.json");
pub const ROOT_MODEL_ABI_JSON: &str = include_str!("../../contracts/airegistry/RootModel.abi.json");
pub const TOKEN_CONTRACT_ABI_JSON: &str =
    include_str!("../../contracts/airegistry/TokenContract.abi.json");
pub const MANIFEST_METADATA_ABI_JSON: &str =
    include_str!("../../contracts/airegistry/ManifestMetadata.abi.json");
pub const GIVER_ABI_JSON: &str = include_str!("../../contracts/giver/GiverV3.abi.json");

// ---- embedded TVCs (stateInit: code + data) ----
pub const SUPER_ROOT_TVC: &[u8] = include_bytes!("../../contracts/airegistry/SuperRoot.tvc");
pub const ROOT_MODEL_TVC: &[u8] = include_bytes!("../../contracts/airegistry/RootModel.tvc");
pub const TOKEN_CONTRACT_TVC: &[u8] =
    include_bytes!("../../contracts/airegistry/TokenContract.tvc");
pub const MANIFEST_METADATA_TVC: &[u8] =
    include_bytes!("../../contracts/airegistry/ManifestMetadata.tvc");

/// Which airegistry contract an artifact belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contract {
    SuperRoot,
    RootModel,
    TokenContract,
    ManifestMetadata,
}

impl Contract {
    pub fn abi_json(self) -> &'static str {
        match self {
            Contract::SuperRoot => SUPER_ROOT_ABI_JSON,
            Contract::RootModel => ROOT_MODEL_ABI_JSON,
            Contract::TokenContract => TOKEN_CONTRACT_ABI_JSON,
            Contract::ManifestMetadata => MANIFEST_METADATA_ABI_JSON,
        }
    }

    pub fn tvc(self) -> &'static [u8] {
        match self {
            Contract::SuperRoot => SUPER_ROOT_TVC,
            Contract::RootModel => ROOT_MODEL_TVC,
            Contract::TokenContract => TOKEN_CONTRACT_TVC,
            Contract::ManifestMetadata => MANIFEST_METADATA_TVC,
        }
    }

    /// Parse the embedded ABI into a `tvm_abi::Contract`.
    pub fn load_abi(self) -> Result<tvm_abi::Contract> {
        tvm_abi::Contract::load(self.abi_json().as_bytes())
            .map_err(|e| anyhow!("load {self:?} ABI: {e}"))
    }

    /// The contract's code cell (extracted from the embedded TVC stateInit).
    pub fn code_cell(self) -> Result<tvm_types::Cell> {
        let cell = tvm_types::read_single_root_boc(self.tvc())
            .map_err(|e| anyhow!("read {self:?} TVC BOC: {e}"))?;
        let state_init = StateInit::construct_from_cell(cell)
            .map_err(|e| anyhow!("parse {self:?} StateInit: {e}"))?;
        state_init
            .code
            .ok_or_else(|| anyhow!("{self:?} TVC has no code cell"))
    }

    /// Hex `tvm.hash` of the contract's code cell — the value `RootModel`/
    /// `SuperRoot` lock against and the value GraphQL reports as `code_hash`.
    pub fn code_hash(self) -> Result<String> {
        Ok(hex::encode(self.code_cell()?.repr_hash().as_slice()))
    }

    /// Base64 BOC of the contract's code cell — what the `cell`-typed
    /// constructor params (`rootModelCode`, `manifestCode`, `tokenContractCode`)
    /// expect (upstream `common.get_code`).
    pub fn code_boc_b64(self) -> Result<String> {
        use base64::Engine;
        let boc = tvm_types::write_boc(&self.code_cell()?)
            .map_err(|e| anyhow!("write {self:?} code BOC: {e}"))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(boc))
    }
}

/// Verify the embedded TVCs match the configured code hashes. Returns an error
/// naming the first mismatch (drifted vendored artifact or stale config).
///
/// `SuperRoot` itself has no configured hash here (it is the top of the tree and
/// is identified by address/pubkey, not locked by a parent); the three locked
/// child codes are the ones the contracts enforce.
pub fn verify_code_hashes(cfg: &crate::config::AiRegistryConfig) -> Result<()> {
    let checks = [
        (
            Contract::RootModel,
            cfg.root_model_code_hash.as_str(),
            "root_model_code_hash",
        ),
        (
            Contract::ManifestMetadata,
            cfg.manifest_metadata_code_hash.as_str(),
            "manifest_metadata_code_hash",
        ),
        (
            Contract::TokenContract,
            cfg.token_contract_code_hash.as_str(),
            "token_contract_code_hash",
        ),
    ];
    for (contract, expected, field) in checks {
        let actual = contract
            .code_hash()
            .with_context(|| format!("hashing {contract:?} code"))?;
        let expected = expected.trim_start_matches("0x");
        if !actual.eq_ignore_ascii_case(expected) {
            bail!(
                "airegistry code-hash mismatch for {contract:?} (config.{field}): \
                 embedded TVC = {actual}, config = {expected}. \
                 Update the vendored TVC or the config hash."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AiRegistryConfig;

    #[test]
    fn all_abis_load() {
        for c in [
            Contract::SuperRoot,
            Contract::RootModel,
            Contract::TokenContract,
            Contract::ManifestMetadata,
        ] {
            c.load_abi().unwrap_or_else(|e| panic!("{c:?}: {e}"));
        }
        // Giver ABI loads too.
        tvm_abi::Contract::load(GIVER_ABI_JSON.as_bytes()).expect("giver abi");
    }

    #[test]
    fn each_tvc_has_a_code_cell_and_64hex_hash() {
        for c in [
            Contract::SuperRoot,
            Contract::RootModel,
            Contract::TokenContract,
            Contract::ManifestMetadata,
        ] {
            let h = c.code_hash().unwrap_or_else(|e| panic!("{c:?}: {e}"));
            assert_eq!(h.len(), 64, "{c:?} code hash not 32 bytes: {h}");
            assert!(h.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn embedded_tvcs_match_shellnet_config_hashes() {
        // This is the load-time hash-lock assertion: it proves the vendored
        // RootModel / ManifestMetadata / TokenContract bytecode is exactly the
        // hash-locked code the airegistry constants enforce. If this fails, the
        // vendored artifact drifted from the config (or vice versa).
        verify_code_hashes(&AiRegistryConfig::shellnet())
            .expect("embedded TVC code hashes must match shellnet config");
    }

    #[test]
    fn mismatch_is_reported() {
        let mut cfg = AiRegistryConfig::shellnet();
        cfg.token_contract_code_hash = "00".repeat(32);
        let err = verify_code_hashes(&cfg).unwrap_err().to_string();
        assert!(err.contains("TokenContract"), "unexpected: {err}");
        assert!(err.contains("mismatch"));
    }
}
