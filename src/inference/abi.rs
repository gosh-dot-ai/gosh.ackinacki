// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Embedded ABIs for the inference-market contract family.
//!
//! Deliberately **lean** (no halo2 / `private-note` feature needed): reading the
//! market — the order book and its events — is pure ABI decode + HTTP. The same
//! `RootPN` / `PrivateNote` ABI files are also embedded by
//! `crate::private_note::artifacts` for the (heavy, optional) minting path; here
//! they only decode events.

use anyhow::{anyhow, Result};
use tvm_abi::Contract;

/// Per-model order book (`InferenceOrderBook.sol`): open orders, best bid/ask,
/// fills, subscriptions. Deployed one per model (from a PrivateNote).
pub const INFERENCE_ORDER_BOOK_ABI_JSON: &str =
    include_str!("../../contracts/dex/InferenceOrderBook.abi.json");

/// A trader's PrivateNote — emits the note-side order confirmations
/// (`InferenceOrderPlacedConfirmed`, `OrderFilledConfirmed`, transfers, …).
pub const PRIVATE_NOTE_ABI_JSON: &str = include_str!("../../contracts/dex/PrivateNote.abi.json");

/// The RootPN system contract — emits `VoucherGenerated` / `PrivateNoteDeployed`
/// (note lifecycle).
pub const ROOT_PN_ABI_JSON: &str = include_str!("../../contracts/dex/RootPN.abi.json");

pub fn order_book_abi() -> Result<Contract> {
    Contract::load(INFERENCE_ORDER_BOOK_ABI_JSON.as_bytes())
        .map_err(|e| anyhow!("load InferenceOrderBook ABI: {e}"))
}

pub fn note_abi() -> Result<Contract> {
    Contract::load(PRIVATE_NOTE_ABI_JSON.as_bytes())
        .map_err(|e| anyhow!("load PrivateNote ABI: {e}"))
}

pub fn root_pn_abi() -> Result<Contract> {
    Contract::load(ROOT_PN_ABI_JSON.as_bytes()).map_err(|e| anyhow!("load RootPN ABI: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_inference_abis_load() {
        assert!(order_book_abi().unwrap().events().len() >= 9);
        assert!(!note_abi().unwrap().events().is_empty());
        assert!(!root_pn_abi().unwrap().events().is_empty());
    }
}
