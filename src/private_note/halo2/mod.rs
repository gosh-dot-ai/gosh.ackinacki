// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Halo2 deposit-voucher proving pipeline for DEX PrivateNotes.

pub mod cache;
pub mod live;
pub mod multisig_voucher;
pub mod paths;
pub mod proof;
pub mod sk_commit;

pub use live::Halo2Proof;
