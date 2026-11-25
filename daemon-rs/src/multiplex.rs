//! Terminal multiplex (Fase 3 M4 slice 3b): the binary stream
//! protocol's server side, per connection. The client opens it
//! with the `terminal.multiplex` RPC (answered `{type:'ready'}`),
//! then speaks stream frames over the sealed binary channel:
//!
//!   client -> Subscribe (streamId 0, payload names the real
//!             streamId + terminal handle), Input, Resize,
//!             ClaimViewport, Unsubscribe, SnapshotRequest, Ack
//!   server -> SnapshotStart {kind:'scrollback'} / SnapshotChunk /
//!             SnapshotEnd, then Output frames as the PTY produces
//!
//! Shapes mirror upstream's terminal-multiplex-* methods and the
//! client transport fixtures. Subset limits (documented in
//! FASE3-PLAN): no outputAck credit window enforcement, no
//! resume ledger, no viewport-claim arbitration — one stream
//! drives its terminal's size, last resize wins.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::task::JoinHandle;

use crate::pty::PtyManager;
use crate::stream::{self, opcode, Frame};
use crate::Outbound;

/// Payload bytes per SnapshotChunk / Output frame.
const FRAME_CHUNK_BYTES: usize = 64 * 1024;
/// Live-output pump cadence.
const PUMP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(40);

struct StreamState {
    terminal: String,
    /// Last sequence number used on this stream (frames count up
    /// from 1), shared with the pump task.
    seq: Arc<Mutex<u64>>,
    pump: JoinHandle<()>,
}

pub struct Multiplex {
    pty: Arc<Mutex<PtyManager>>,
    outbound: Outbound,
    streams: HashMap<u32, StreamState>,
}

impl Multiplex {
    pub fn new(pty: Arc<Mutex<PtyManager>>, outbound: Outbound) -> Multiplex {
        Multiplex { pty, outbound, streams: HashMap::new() }
    }

    /// Routes one decrypted binary payload. Non-stream bytes and
    /// frames for unknown streams are ignored, like upstream's
    /// binary message router.
    pub async fn on_binary(&mut self, bytes: &[u8]) {
        let Some(frame) = stream::decode(bytes) else { return };
        match frame.opcode {
            opcode::SUBSCRIBE if frame.stream_id == 0 => self.on_subscribe(&frame).await,
            opcode::INPUT => {
                if let Some(stream) = self.streams.get(&frame.stream_id) {
                    let terminal = stream.terminal.clone();
                    if let Ok(mut pty) = self.pty.lock() {
                        let _ = pty.write(&terminal, &frame.payload);
                    }
                }
            }
            opcode::RESIZE | opcode::CLAIM_VIEWPORT => {
                if let Some(stream) = self.streams.get(&frame.stream_id) {
                    if let Some((cols, rows)) = parse_viewport(&frame.payload) {
                        let terminal = stream.terminal.clone();
                        if let Ok(mut pty) = self.pty.lock() {
                            let _ = pty.resize(&terminal, cols, rows);
                        }
                    }
                }
            }
            opcode::UNSUBSCRIBE => {
                if let Some(stream) = self.streams.remove(&frame.stream_id) {
                    stream.pump.abort();
                }
            }
            opcode::SNAPSHOT_REQUEST => {
                if let Some(stream) = self.streams.get(&frame.stream_id) {
                    let terminal = stream.terminal.clone();
                    let seq = stream.seq.clone();
                    self.send_snapshot(frame.stream_id, &terminal, &seq).await;
                }
            }
            // Ack / SetOutputPaused / SetOutputCadence: accepted
            // and ignored — the subset sends output uncredited.
            _ => {}
        }
    }

    async fn on_subscribe(&mut self, frame: &Frame) {
        let Some(payload) = stream::decode_json(&frame.payload) else { return };
        let Some(stream_id) = payload
            .get("streamId")
            .and_then(|v| v.as_u64())
            .filter(|id| *id >= 1 && *id <= u32::MAX as u64)
            .map(|id| id as u32)
        else {
            return;
        };
        let Some(terminal) = payload.get("terminal").and_then(|v| v.as_str()) else {
            return;
        };
        let terminal = terminal.to_string();
        // A viewport in the subscribe payload sizes the PTY
        // before the snapshot, like upstream's subscribe path.
        if let Some(viewport) = payload.get("viewport") {
            if let (Some(cols), Some(rows)) = (
                viewport.get("cols").and_then(|v| v.as_u64()),
                viewport.get("rows").and_then(|v| v.as_u64()),
            ) {
                if let Ok(mut pty) = self.pty.lock() {
                    let _ = pty.resize(&terminal, cols as u16, rows as u16);
                }
            }
        }
        // A reused stream id replaces its predecessor.
        if let Some(old) = self.streams.remove(&stream_id) {
            old.pump.abort();
        }
        let seq = Arc::new(Mutex::new(0u64));
        let snapshot_end = self.send_snapshot(stream_id, &terminal, &seq).await;
        let Some(mut cursor) = snapshot_end else {
            // Unknown terminal: report on the stream and stop.
            let error = Frame {
                opcode: opcode::ERROR,
                stream_id,
                seq: next_seq(&seq),
                payload: stream::encode_json(&json!({ "message": "unknown terminal" })),
            };
            let _ = self.outbound.send_binary(&stream::encode(&error)).await;
            return;
        };
        let pty = self.pty.clone();
        let outbound = self.outbound.clone();
        let pump_seq = seq.clone();
        let pump_terminal = terminal.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::time::sleep(PUMP_INTERVAL).await;
                let batch = {
                    let Ok(pty) = pty.lock() else { break };
                    match pty.read(&pump_terminal, cursor) {
                        Ok((start, bytes, end)) => {
                            let exited = pty
                                .list()
                                .iter()
                                .find(|info| info.id == pump_terminal)
                                .map(|info| info.state == crate::pty::SessionState::Exited)
                                .unwrap_or(true);
                            (start, bytes, end, exited)
                        }
                        Err(_) => break,
                    }
                };
                let (start, bytes, end, exited) = batch;
                if start > cursor {
                    // Bytes aged out of the ring buffer; resume
                    // from what is retained rather than stalling.
                    cursor = start;
                }
                if !bytes.is_empty() {
                    cursor = end;
                    for chunk in bytes.chunks(FRAME_CHUNK_BYTES) {
                        let frame = Frame {
                            opcode: opcode::OUTPUT,
                            stream_id,
                            seq: next_seq(&pump_seq),
                            payload: chunk.to_vec(),
                        };
                        if !outbound.send_binary(&stream::encode(&frame)).await {
                            return;
                        }
                    }
                }
                if exited && cursor >= end {
                    break;
                }
            }
        });
        self.streams.insert(stream_id, StreamState { terminal, seq, pump });
    }

    /// Sends the scrollback snapshot (Start / Chunks / End) from
    /// the ring buffer. Returns the byte cursor the live pump
    /// should continue from, or None for an unknown terminal.
    async fn send_snapshot(
        &self,
        stream_id: u32,
        terminal: &str,
        seq: &Arc<Mutex<u64>>,
    ) -> Option<u64> {
        let (bytes, end) = {
            let pty = self.pty.lock().ok()?;
            let (_start, bytes, end) = pty.read(terminal, 0).ok()?;
            (bytes, end)
        };
        let start = Frame {
            opcode: opcode::SNAPSHOT_START,
            stream_id,
            seq: next_seq(seq),
            payload: stream::encode_json(&json!({ "kind": "scrollback" })),
        };
        if !self.outbound.send_binary(&stream::encode(&start)).await {
            return None;
        }
        for chunk in bytes.chunks(FRAME_CHUNK_BYTES) {
            let frame = Frame {
                opcode: opcode::SNAPSHOT_CHUNK,
                stream_id,
                seq: next_seq(seq),
                payload: chunk.to_vec(),
            };
            if !self.outbound.send_binary(&stream::encode(&frame)).await {
                return None;
            }
        }
        let end_frame = Frame {
            opcode: opcode::SNAPSHOT_END,
            stream_id,
            seq: next_seq(seq),
            payload: Vec::new(),
        };
        if !self.outbound.send_binary(&stream::encode(&end_frame)).await {
            return None;
        }
        Some(end)
    }

    /// Connection closing: stop every pump.
    pub fn shutdown(&mut self) {
        for (_, stream) in self.streams.drain() {
            stream.pump.abort();
        }
    }
}

fn next_seq(seq: &Arc<Mutex<u64>>) -> u64 {
    let Ok(mut seq) = seq.lock() else { return 0 };
    *seq += 1;
    *seq
}

fn parse_viewport(payload: &[u8]) -> Option<(u16, u16)> {
    let value = stream::decode_json(payload)?;
    let cols = value.get("cols")?.as_u64()?;
    let rows = value.get("rows")?.as_u64()?;
    Some((cols.min(u16::MAX as u64) as u16, rows.min(u16::MAX as u64) as u16))
}
