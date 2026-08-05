// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT
//
// Extracted from ackinacki/block-manager block_subscriber.rs
// Original: 2022-2025 (c) Contributors to the GOSH DAO.

use std::net::SocketAddr;
use std::sync::mpsc;

use anyhow::bail;
use transport_layer::msquic::MsQuicTransport;
use transport_layer::NetConnection;
use transport_layer::NetCredential;
use transport_layer::NetTransport;

use crate::BlockCommand;

/// Single connection attempt: connect to a BK node, receive blocks until error.
pub async fn run_once(
    tx: &mpsc::Sender<BlockCommand>,
    socket_addr: SocketAddr,
) -> anyhow::Result<()> {
    let transport = MsQuicTransport::new();
    let conn = match transport
        .connect(
            socket_addr,
            &["ALPN"],
            NetCredential::generate_self_signed(Some(vec![socket_addr.to_string()]), &[])?,
        )
        .await
    {
        Ok(conn) => {
            tracing::info!(peer = socket_addr.to_string(), "connected to BK node");
            conn
        }
        Err(error) => {
            tracing::error!("can't connect to {socket_addr}: {error}");
            bail!("can't connect to {socket_addr}: {error}");
        }
    };

    loop {
        match conn.recv().await {
            Ok((message, duration)) => {
                tracing::debug!(
                    duration_ms = duration.as_millis(),
                    bytes = message.len(),
                    "block received",
                );
                if tx.send(BlockCommand::Data(message)).is_err() {
                    bail!("receiver dropped, stopping subscriber");
                }
            }
            Err(error) => {
                tracing::error!("recv error from {socket_addr}: {error}");
                bail!("recv error from {socket_addr}: {error}");
            }
        }
    }
}

/// Infinite retry loop wrapping `run_once`.
pub async fn run(tx: mpsc::Sender<BlockCommand>, socket_addr: SocketAddr) -> anyhow::Result<()> {
    loop {
        if let Err(e) = run_once(&tx, socket_addr).await {
            tracing::warn!("connection to {socket_addr} failed: {e}, retrying in 1s");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}
