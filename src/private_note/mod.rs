// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! DEX PrivateNote minting primitives.
//!
//! This module ports the wallet-funded `RootPN.generateVoucher` ->
//! `RootPN.deployPrivateNote` -> `RootPN.sendEccShellToPrivateNote` path from
//! `gosh-sh/dexdo` into this crate so consumers do not have to shell out to the
//! old `onboard_user_shellnet` binary or pull a second TVM SDK.

pub mod artifacts;
pub mod halo2;
pub mod onboard;
pub mod proof;
pub mod voucher_event;

pub use halo2::paths::{Halo2Paths, Halo2PathsError};
pub use onboard::{
    deploy_private_note_from_multisig, DeployPrivateNoteParams, DeployPrivateNoteResult,
};
pub use proof::{Nominal, TokenType};
