// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! Acki Nacki blockchain integration layer for GOSH.AI.
//!
//! Two planes (see `docs/ARCHITECTURE.md`):
//! - **default (lean)** — a thin chain client over the Block Manager GraphQL /
//!   HTTP API: account reads + local getters ([`airegistry::getter`] /
//!   [`airegistry::run`]), event reads, signed writes ([`wallet`]), the
//!   AI Registry surface, and crypto. No `node`, no MsQuic.
//! - **`block-stream` feature** — the full-agent indexer: a QUIC firehose from
//!   Block Keeper nodes ([`transport`] → [`decoder`] → [`filter::engine`] →
//!   [`transform`]) ingested into gosh.memory. Pulls `node` + `transport-layer`
//!   + MsQuic.

pub mod airegistry;
pub mod client;
pub mod config;
pub mod filter;
pub mod inference;
pub mod mcp;
#[cfg(feature = "private-note")]
pub mod private_note;
pub mod sdk;
pub mod state;
pub mod wallet;

// ---- block-stream indexer (feature-gated; pulls node/transport/MsQuic) ----
#[cfg(feature = "block-stream")]
pub mod decoder;
#[cfg(feature = "block-stream")]
pub mod transform;
#[cfg(feature = "block-stream")]
pub mod transport;

/// Commands sent from transport to decoder worker.
#[cfg(feature = "block-stream")]
pub enum BlockCommand {
    /// Raw block bytes received from a BK node.
    Data(Vec<u8>),
    /// Graceful shutdown.
    Shutdown(tokio::sync::oneshot::Sender<()>),
}
