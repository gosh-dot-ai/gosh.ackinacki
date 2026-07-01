// Copyright 2026 (c) Mitja Goroshevsky and GOSH Technology Ltd.
// SPDX-License-Identifier: MIT
//
// Block deserialization extracted from ackinacki/block-manager.
// Original: 2022-2025 (c) Contributors to the GOSH DAO.

use std::sync::mpsc;

use node::bls::envelope::BLSSignedEnvelope;
use node::bls::envelope::Envelope;
use node::types::AckiNackiBlock;
use transport_layer::HostPort;

use crate::decoder::dedup::RecentBlockFilter;
use crate::BlockCommand;

/// Decoded block with metadata stripped from the wire envelope.
pub struct DecodedBlock {
    /// Source BK node address (if present in envelope).
    pub source: Option<HostPort>,
    /// The deserialized block.
    pub envelope: Envelope<AckiNackiBlock>,
}

/// Deserialize raw bytes from the wire into a block envelope.
///
/// Wire format (two-layer bincode):
///   Layer 1: (Option<HostPort>, Vec<u8>)
///   Layer 2: Envelope<AckiNackiBlock>
pub fn deserialize(raw: &[u8]) -> anyhow::Result<DecodedBlock> {
    let (source, block_bytes) = bincode::deserialize::<(Option<HostPort>, Vec<u8>)>(raw)?;
    let envelope: Envelope<AckiNackiBlock> = bincode::deserialize(&block_bytes)?;
    Ok(DecodedBlock { source, envelope })
}

/// Decoder worker: receives raw blocks from transport, deserializes,
/// deduplicates, and forwards decoded blocks via callback.
///
/// `on_block` is called for each new (non-duplicate) block.
/// This is where the filter (step 3) will plug in.
pub fn run<F>(cmd_rx: mpsc::Receiver<BlockCommand>, mut on_block: F) -> anyhow::Result<()>
where
    F: FnMut(DecodedBlock) -> anyhow::Result<()>,
{
    let mut dedup = RecentBlockFilter::default();

    loop {
        match cmd_rx.recv() {
            Ok(BlockCommand::Data(raw)) => {
                let decoded = match deserialize(&raw) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!("block deserialization failed: {e}");
                        continue;
                    }
                };

                let block_hash = *decoded.envelope.data().hash();
                if !dedup.check_and_insert(block_hash) {
                    tracing::debug!("duplicate block skipped");
                    continue;
                }

                let seq_no = decoded.envelope.data().seq_no();
                let thread_id = *decoded.envelope.data().common_section().thread_id();
                tracing::debug!(
                    seq_no = ?seq_no,
                    thread = ?thread_id,
                    "block decoded",
                );

                if let Err(e) = on_block(decoded) {
                    tracing::error!("block handler error: {e}");
                }
            }
            Ok(BlockCommand::Shutdown(tx)) => {
                tracing::info!("decoder shutdown");
                let _ = tx.send(());
                return Ok(());
            }
            Err(e) => {
                anyhow::bail!("channel closed: {e}");
            }
        }
    }
}
