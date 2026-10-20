// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT

//! The **inference market**, read-side: the per-model order book and its event
//! stream (orders placed / filled / cancelled, private-note activity).
//!
//! This module is **lean** — plain ABI decode + Block Manager HTTP, no halo2,
//! no `private-note` feature, no node. It covers:
//! - [`book::fetch_order_book`] — a consistent snapshot of ALL open orders
//!   (bids/asks, best bid/ask, stats) reconstructed from one BOC fetch;
//! - [`events::InferenceEvent`] + [`events::decode_event_body_b64`] — typed
//!   market events for feeds (Plane A `read_events_with`) and for the
//!   block-stream filter (Plane B `MatchedMessage` bodies);
//! - [`abi`] — the embedded `InferenceOrderBook` / `PrivateNote` / `RootPN`
//!   ABIs.
//!
//! *Writing* to the market (posting offers, buying inference, minting the
//! funding notes) lives in the optional [`crate::private_note`] feature — a
//! seller/buyer needs it; a dashboard, indexer, or market watcher needs only
//! this module. Convenience wrappers:
//! [`crate::sdk::ChainClient::inference_order_book`] and
//! [`crate::sdk::ChainClient::subscribe_inference_events`].

pub mod abi;
pub mod book;
pub mod events;

pub use book::{fetch_order_book, BookStats, OpenOrder, OrderBookSnapshot};
pub use events::{decode_event_body_b64, InferenceAbis, InferenceEvent};
