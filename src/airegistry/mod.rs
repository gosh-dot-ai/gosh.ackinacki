// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! AI Registry (airegistry / SPC token contracts) wrapper.
//!
//! On-chain AI-model token marketplace built on the airegistry contracts
//! (`SuperRoot / RootModel / TokenContract / ManifestMetadata`).

pub mod abi;
pub mod calls;
pub mod deploy;
pub mod errors;
pub mod events;
pub mod getter;
pub mod run;
pub mod signer;
pub mod store;
