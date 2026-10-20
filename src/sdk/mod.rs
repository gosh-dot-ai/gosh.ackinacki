// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! `gosh_ackinacki::sdk` — the stable, lean library facade.
//!
//! Thin wrappers over the existing chain / wallet / crypto layers (no logic
//! changes) so an external consumer gets a small, typed surface without
//! depending on the block-stream indexer or the MCP server. Built entirely on
//! the default (lean) feature set: Block Manager HTTP/GraphQL only, no `node` /
//! MsQuic.
//!
//! Exposed today:
//! - value types [`Address`], [`Pubkey`], [`Signature`];
//! - [`KeyPair`] — the ed25519 signing identity;
//! - [`ChainClient`] — connect / get_account (+balances) / run_getter / call /
//!   deploy / chain_liveness / subscribe_events over the Block Manager;
//! - [`Wallet`] — a multisig (`SwarmMultisigWallet`) submit/confirm handle.
//!
//! On keys: the SDK exposes only the **ed25519** signing key — the credential a
//! chain consumer holds to sign its own transactions. **X25519** sealed-secret
//! delivery (gosh.memory, [`crate::client::sealed_secrets`]) is deliberately
//! NOT here: it is an *agent's* root identity for receiving credentials, a
//! different layer with a different lifecycle (one per agent vs many signing
//! keys it custodies). Conflating them would weld money into agent identity.

pub mod client;
pub mod keys;
pub mod sealedbox;
pub mod types;
pub mod wallet;

pub use client::{Account, ChainClient};
pub use keys::KeyPair;
pub use sealedbox::{BoxKey, SealedMessage};
pub use types::{Address, Pubkey, Signature};
pub use wallet::Wallet;

// Types surfaced by `ChainClient` (liveness + the event subscription stream).
pub use crate::airegistry::events::AiRegistryEvent;
pub use crate::airegistry::getter::{ChainLiveness, EventRecord};
// Inference market (order book snapshot + typed market events).
pub use crate::inference::{BookStats, InferenceEvent, OpenOrder, OrderBookSnapshot};
