//! Terminal stream frame codec (Fase 3 M4 slice 3): the binary
//! multiplex protocol the web client uses for terminal I/O,
//! mirrored byte-for-byte from upstream's
//! `src/shared/terminal/stream/terminal-stream-protocol.ts`.
//!
//! Frame layout (16-byte header + payload):
//!   [0]    kind byte 0x74 ('t')
//!   [1]    version 1
//!   [2]    opcode
//!   [3]    reserved 0
//!   [4..8] stream id, u32 little-endian
//!   [8..16] sequence, u64 split as two LE u32 (high then low)

pub const KIND: u8 = 0x74;
pub const VERSION: u8 = 1;
pub const HEADER_BYTES: usize = 16;

pub mod opcode {
    pub const OUTPUT: u8 = 1;
    pub const SNAPSHOT_START: u8 = 2;
    pub const SNAPSHOT_CHUNK: u8 = 3;
    pub const SNAPSHOT_END: u8 = 4;
    pub const RESIZED: u8 = 5;
    pub const ERROR: u8 = 6;
    pub const INPUT: u8 = 7;
    pub const RESIZE: u8 = 8;
    pub const SUBSCRIBE: u8 = 9;
    pub const UNSUBSCRIBE: u8 = 10;
    pub const SNAPSHOT_REQUEST: u8 = 11;
    pub const METADATA: u8 = 12;
    pub const ACK: u8 = 13;
    pub const CLAIM_VIEWPORT: u8 = 14;
    pub const OUTPUT_SPAN: u8 = 15;
    pub const SET_OUTPUT_PAUSED: u8 = 16;
    pub const WRITE_UNAVAILABLE: u8 = 17;
    pub const INPUT_ACK: u8 = 18;
    pub const PAUSED_OUTPUT_DROPPED: u8 = 19;
    pub const SET_OUTPUT_CADENCE: u8 = 20;
}

fn is_opcode(value: u8) -> bool {
    (opcode::OUTPUT..=opcode::SET_OUTPUT_CADENCE).contains(&value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: u8,
    pub stream_id: u32,
    pub seq: u64,
    pub payload: Vec<u8>,
}

pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES + frame.payload.len());
    out.push(KIND);
    out.push(VERSION);
    out.push(frame.opcode);
    out.push(0);
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&((frame.seq >> 32) as u32).to_le_bytes());
    out.extend_from_slice(&(frame.seq as u32).to_le_bytes());
    out.extend_from_slice(&frame.payload);
    out
}

pub fn decode(bytes: &[u8]) -> Option<Frame> {
    if bytes.len() < HEADER_BYTES || bytes[0] != KIND || bytes[1] != VERSION {
        return None;
    }
    let opcode = bytes[2];
    if !is_opcode(opcode) {
        return None;
    }
    let stream_id = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let high = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as u64;
    let low = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as u64;
    Some(Frame {
        opcode,
        stream_id,
        seq: high * 0x1_0000_0000 + low,
        payload: bytes[HEADER_BYTES..].to_vec(),
    })
}

pub fn encode_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

pub fn decode_json(payload: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_slice(payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_frame_layout() {
        // Mirrors encodeTerminalStreamFrame for
        // {opcode: Output, streamId: 0x01020304, seq: 2^32 + 2}.
        let frame = Frame {
            opcode: opcode::OUTPUT,
            stream_id: 0x0102_0304,
            seq: 0x1_0000_0002,
            payload: b"hi".to_vec(),
        };
        let bytes = encode(&frame);
        assert_eq!(
            bytes,
            vec![
                0x74, 0x01, 0x01, 0x00, // kind, version, opcode, reserved
                0x04, 0x03, 0x02, 0x01, // stream id LE
                0x01, 0x00, 0x00, 0x00, // seq high LE
                0x02, 0x00, 0x00, 0x00, // seq low LE
                b'h', b'i',
            ]
        );
        assert_eq!(decode(&bytes), Some(frame));
    }

    #[test]
    fn rejects_foreign_and_short_frames() {
        assert_eq!(decode(&[0x74, 0x01]), None);
        let mut wrong_kind = encode(&Frame {
            opcode: opcode::INPUT,
            stream_id: 1,
            seq: 0,
            payload: Vec::new(),
        });
        wrong_kind[0] = 0x00;
        assert_eq!(decode(&wrong_kind), None);
        let mut bad_opcode = encode(&Frame {
            opcode: opcode::INPUT,
            stream_id: 1,
            seq: 0,
            payload: Vec::new(),
        });
        bad_opcode[2] = 99;
        assert_eq!(decode(&bad_opcode), None);
    }

    #[test]
    fn json_payload_round_trip() {
        let payload = encode_json(&serde_json::json!({ "cols": 120, "rows": 40 }));
        let parsed = decode_json(&payload).unwrap();
        assert_eq!(parsed["cols"], 120);
        assert_eq!(parsed["rows"], 40);
    }
}
