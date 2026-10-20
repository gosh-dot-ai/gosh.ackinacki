// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Embedded DEX PrivateNote ABIs.

use anyhow::{anyhow, Result};

pub const ROOT_PN_ABI_JSON: &str = include_str!("../../contracts/dex/RootPN.abi.json");
pub const PRIVATE_NOTE_ABI_JSON: &str = include_str!("../../contracts/dex/PrivateNote.abi.json");

pub fn root_pn_abi() -> Result<tvm_abi::Contract> {
    tvm_abi::Contract::load(ROOT_PN_ABI_JSON.as_bytes())
        .map_err(|e| anyhow!("load RootPN ABI: {e}"))
}

pub fn private_note_abi() -> Result<tvm_abi::Contract> {
    tvm_abi::Contract::load(PRIVATE_NOTE_ABI_JSON.as_bytes())
        .map_err(|e| anyhow!("load PrivateNote ABI: {e}"))
}
