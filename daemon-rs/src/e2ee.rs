//! E2EE v2 core, ported bit-compatibly from upstream
//! `src/shared/remote-runtime/e2ee/` (contract, transcript, key
//! schedule). Verified against upstream's own test vector in
//! `mobile-e2ee-v2-fixtures.ts` — see the tests at the bottom.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const TRANSCRIPT_DOMAIN: &str = "orca-mobile-e2ee/v2/transcript";
const SALT_LABEL: &[u8] = b"orca-mobile-e2ee/v2/salt\0";
const INFO_LABEL: &[u8] = b"orca-mobile-e2ee/v2/session\0";

/// The handshake values the transcript and key schedule bind. Mirrors
/// MobileE2EEV2Handshake with the hello/ready context flattened (the
/// two contexts are required to be identical by validation upstream).
pub struct Handshake {
    pub client_public_key: [u8; 32],
    pub client_nonce: [u8; 32],
    pub desktop_public_key: [u8; 32],
    pub desktop_nonce: [u8; 32],
    pub transport: String,
    pub relay_host_id: Option<String>,
}

fn u32be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn number_list(values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32be(values.len() as u32));
    for value in values {
        out.extend_from_slice(&u32be(*value));
    }
    out
}

fn string_list(values: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32be(values.len() as u32));
    for value in values {
        out.extend_from_slice(&u32be(value.len() as u32));
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// encodeMobileE2EEV2Transcript: fixed-order labeled fields, each
/// uint32BE(name_len) || name || uint32BE(value_len) || value.
pub fn encode_transcript(h: &Handshake) -> Vec<u8> {
    let relay = h.relay_host_id.as_deref().unwrap_or("");
    let fields: Vec<(&str, Vec<u8>)> = vec![
        ("domain", TRANSCRIPT_DOMAIN.as_bytes().to_vec()),
        ("mobile-to-desktop.type", b"e2ee_hello".to_vec()),
        ("mobile-to-desktop.version", u32be(2).to_vec()),
        ("mobile-to-desktop.client-public-key", h.client_public_key.to_vec()),
        ("mobile-to-desktop.client-nonce", h.client_nonce.to_vec()),
        ("mobile-to-desktop.capabilities.framing", number_list(&[2])),
        (
            "mobile-to-desktop.capabilities.payload-kinds",
            string_list(&["text", "binary"]),
        ),
        ("mobile-to-desktop.context.protocol", b"orca-mobile-e2ee".to_vec()),
        ("mobile-to-desktop.context.initiator", b"mobile".to_vec()),
        ("mobile-to-desktop.context.responder", b"desktop".to_vec()),
        ("mobile-to-desktop.context.transport", h.transport.as_bytes().to_vec()),
        ("mobile-to-desktop.context.relay-host-id", relay.as_bytes().to_vec()),
        ("desktop-to-mobile.type", b"e2ee_ready".to_vec()),
        ("desktop-to-mobile.version", u32be(2).to_vec()),
        ("desktop-to-mobile.desktop-public-key", h.desktop_public_key.to_vec()),
        ("desktop-to-mobile.client-nonce-echo", h.client_nonce.to_vec()),
        ("desktop-to-mobile.desktop-nonce", h.desktop_nonce.to_vec()),
        ("desktop-to-mobile.selection.framing", u32be(2).to_vec()),
        (
            "desktop-to-mobile.selection.payload-kinds",
            string_list(&["text", "binary"]),
        ),
        ("desktop-to-mobile.context.protocol", b"orca-mobile-e2ee".to_vec()),
        ("desktop-to-mobile.context.initiator", b"mobile".to_vec()),
        ("desktop-to-mobile.context.responder", b"desktop".to_vec()),
        ("desktop-to-mobile.context.transport", h.transport.as_bytes().to_vec()),
        ("desktop-to-mobile.context.relay-host-id", relay.as_bytes().to_vec()),
    ];
    let mut out = Vec::new();
    for (name, value) in &fields {
        out.extend_from_slice(&u32be(name.len() as u32));
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&u32be(value.len() as u32));
        out.extend_from_slice(value);
    }
    out
}

pub struct KeySchedule {
    pub mobile_to_desktop_key: [u8; 32],
    pub desktop_to_mobile_key: [u8; 32],
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; 32],
}

/// derivePairedE2EEV2KeySchedule: HKDF-SHA256 over the shared secret
/// with a transcript-bound salt/info pair.
pub fn derive_key_schedule(
    shared_secret: &[u8; 32],
    transcript: &[u8],
    client_nonce: &[u8; 32],
    desktop_nonce: &[u8; 32],
) -> KeySchedule {
    let transcript_hash: [u8; 32] = Sha256::digest(transcript).into();
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(SALT_LABEL);
    salt_input.extend_from_slice(client_nonce);
    salt_input.extend_from_slice(desktop_nonce);
    let salt: [u8; 32] = Sha256::digest(&salt_input).into();
    let mut info = Vec::new();
    info.extend_from_slice(INFO_LABEL);
    info.extend_from_slice(&transcript_hash);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut expanded = [0u8; 96];
    hk.expand(&info, &mut expanded).expect("96 bytes is a valid HKDF length");
    let mut mobile_to_desktop_key = [0u8; 32];
    let mut desktop_to_mobile_key = [0u8; 32];
    let mut session_id = [0u8; 32];
    mobile_to_desktop_key.copy_from_slice(&expanded[0..32]);
    desktop_to_mobile_key.copy_from_slice(&expanded[32..64]);
    session_id.copy_from_slice(&expanded[64..96]);
    KeySchedule { mobile_to_desktop_key, desktop_to_mobile_key, session_id, transcript_hash }
}

/// The host's curve25519 public key for a 32-byte secret, as
/// nacl.box.keyPair.fromSecretKey derives it.
pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let secret_key = x25519_dalek::StaticSecret::from(*secret);
    *x25519_dalek::PublicKey::from(&secret_key).as_bytes()
}

/// HSalsa20 (NaCl crypto_core_hsalsa20): the Salsa20 round function
/// over the "expand 32-byte k" state, outputting the diagonal +
/// input words with no feed-forward addition.
fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    const SIGMA: [u8; 16] = *b"expand 32-byte k";
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes.first_chunk::<4>().expect("4 bytes").to_owned());
    let mut x = [0u32; 16];
    x[0] = word(&SIGMA[0..4]);
    x[5] = word(&SIGMA[4..8]);
    x[10] = word(&SIGMA[8..12]);
    x[15] = word(&SIGMA[12..16]);
    for i in 0..4 {
        x[1 + i] = word(&key[i * 4..i * 4 + 4]);
        x[11 + i] = word(&key[16 + i * 4..16 + i * 4 + 4]);
    }
    for i in 0..4 {
        x[6 + i] = word(&input[i * 4..i * 4 + 4]);
    }
    fn quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[b] ^= (x[a].wrapping_add(x[d])).rotate_left(7);
        x[c] ^= (x[b].wrapping_add(x[a])).rotate_left(9);
        x[d] ^= (x[c].wrapping_add(x[b])).rotate_left(13);
        x[a] ^= (x[d].wrapping_add(x[c])).rotate_left(18);
    }
    for _ in 0..10 {
        quarter(&mut x, 0, 4, 8, 12);
        quarter(&mut x, 5, 9, 13, 1);
        quarter(&mut x, 10, 14, 2, 6);
        quarter(&mut x, 15, 3, 7, 11);
        quarter(&mut x, 0, 1, 2, 3);
        quarter(&mut x, 5, 6, 7, 4);
        quarter(&mut x, 10, 11, 8, 9);
        quarter(&mut x, 15, 12, 13, 14);
    }
    let mut out = [0u8; 32];
    for (i, pos) in [0usize, 5, 10, 15, 6, 7, 8, 9].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[*pos].to_le_bytes());
    }
    out
}

/// deriveSharedKey (e2ee/node/e2ee-crypto.ts) = nacl.box.before:
/// HSalsa20(X25519 DH result, zero input) — NOT the raw scalarmult
/// output. The HKDF input depends on this exact form.
pub fn derive_shared_key(our_secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret_key = x25519_dalek::StaticSecret::from(*our_secret);
    let public_key = x25519_dalek::PublicKey::from(*peer_public);
    let dh = secret_key.diffie_hellman(&public_key);
    hsalsa20(dh.as_bytes(), &[0u8; 16])
}

// ---------------------------------------------------------------------------
// Sealed frames (port of e2ee/mobile-e2ee-v2-framing.ts). A frame is
// nonce[24] || secretbox(header[42] || payload); the nonce is derived
// deterministically from sessionId/direction/kind/counter, and the
// header repeats those fields inside the box so a frame cannot be
// replayed, reflected, or re-kinded.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    MobileToDesktop,
    DesktopToMobile,
}

impl Direction {
    fn byte(self) -> u8 {
        match self {
            Direction::MobileToDesktop => 0,
            Direction::DesktopToMobile => 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayloadKind {
    Text,
    Binary,
}

impl PayloadKind {
    fn byte(self) -> u8 {
        match self {
            PayloadKind::Text => 0,
            PayloadKind::Binary => 1,
        }
    }
}

const HEADER_LENGTH: usize = 32 + 1 + 1 + 8;
const NONCE_LENGTH: usize = 24;
const FRAME_VERSION: u8 = 2;
const SECRETBOX_OVERHEAD: usize = 16;

fn encode_header(session_id: &[u8; 32], direction: Direction, kind: PayloadKind, counter: u64) -> [u8; HEADER_LENGTH] {
    let mut header = [0u8; HEADER_LENGTH];
    header[..32].copy_from_slice(session_id);
    header[32] = direction.byte();
    header[33] = kind.byte();
    header[34..42].copy_from_slice(&counter.to_be_bytes());
    header
}

fn encode_nonce(session_id: &[u8; 32], direction: Direction, kind: PayloadKind, counter: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    nonce[..12].copy_from_slice(&session_id[..12]);
    nonce[12] = FRAME_VERSION;
    nonce[13] = direction.byte();
    nonce[14] = kind.byte();
    nonce[15] = 0;
    nonce[16..24].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn seal_frame(
    key: &[u8; 32],
    session_id: &[u8; 32],
    direction: Direction,
    kind: PayloadKind,
    counter: u64,
    payload: &[u8],
) -> Vec<u8> {
    use xsalsa20poly1305::aead::{Aead, KeyInit};
    use xsalsa20poly1305::{Key, Nonce, XSalsa20Poly1305};
    let header = encode_header(session_id, direction, kind, counter);
    let nonce = encode_nonce(session_id, direction, kind, counter);
    let mut plaintext = Vec::with_capacity(HEADER_LENGTH + payload.len());
    plaintext.extend_from_slice(&header);
    plaintext.extend_from_slice(payload);
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let boxed = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .expect("secretbox seal cannot fail for in-memory input");
    let mut frame = Vec::with_capacity(NONCE_LENGTH + boxed.len());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&boxed);
    frame
}

pub fn open_frame(
    key: &[u8; 32],
    session_id: &[u8; 32],
    direction: Direction,
    kind: PayloadKind,
    expected_counter: u64,
    frame: &[u8],
) -> Option<Vec<u8>> {
    use xsalsa20poly1305::aead::{Aead, KeyInit};
    use xsalsa20poly1305::{Key, Nonce, XSalsa20Poly1305};
    if frame.len() < NONCE_LENGTH + SECRETBOX_OVERHEAD + HEADER_LENGTH {
        return None;
    }
    let expected_nonce = encode_nonce(session_id, direction, kind, expected_counter);
    if frame[..NONCE_LENGTH] != expected_nonce {
        return None;
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&expected_nonce), &frame[NONCE_LENGTH..])
        .ok()?;
    let expected_header = encode_header(session_id, direction, kind, expected_counter);
    if plaintext[..HEADER_LENGTH] != expected_header {
        return None;
    }
    Some(plaintext[HEADER_LENGTH..].to_vec())
}

// ---------------------------------------------------------------------------
// Canonical base64 (upstream rejects anything that does not re-encode
// to itself) and the device key proof.
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode_canonical(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    let bytes = B64.decode(value).ok()?;
    if bytes.len() != expected_len || B64.encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}

pub fn b64_decode_canonical_any(value: &str) -> Option<Vec<u8>> {
    let bytes = B64.decode(value).ok()?;
    if B64.encode(&bytes) != value {
        return None;
    }
    Some(bytes)
}

/// verifyDeviceProof (pairing/device-key-proof.ts): an Ed25519
/// signature over "orca-device-proof/v1\0<purpose>\0" || transcriptHash.
pub fn verify_device_proof(
    device_public_key_b64: &str,
    device_proof_b64: &str,
    purpose: &str,
    transcript_hash_b64: &str,
) -> bool {
    let Some(public_key) = b64_decode_canonical(device_public_key_b64, 32) else {
        return false;
    };
    let Some(signature) = b64_decode_canonical(device_proof_b64, 64) else {
        return false;
    };
    let Some(transcript_hash) = b64_decode_canonical(transcript_hash_b64, 32) else {
        return false;
    };
    let mut message = Vec::new();
    message.extend_from_slice(b"orca-device-proof/v1\0");
    message.extend_from_slice(purpose.as_bytes());
    message.push(0);
    message.extend_from_slice(&transcript_hash);
    let Ok(verifying_key) =
        ed25519_dalek::VerifyingKey::from_bytes(public_key.first_chunk::<32>().expect("32 bytes"))
    else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(
        signature.first_chunk::<64>().expect("64 bytes"),
    );
    use ed25519_dalek::Verifier;
    verifying_key.verify(&message, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// The host side of the v2 handshake (port of
// main/runtime/rpc/mobile/e2ee/mobile-e2ee-v2-desktop-session.ts).
// ---------------------------------------------------------------------------

pub struct DesktopSession {
    pub ready: serde_json::Value,
    pub transcript_hash_b64: String,
    mobile_to_desktop_key: [u8; 32],
    desktop_to_mobile_key: [u8; 32],
    session_id: [u8; 32],
    inbound_counter: u64,
    outbound_counter: u64,
}

fn exact_keys(value: &serde_json::Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut wanted: Vec<&str> = expected.to_vec();
    actual.sort_unstable();
    wanted.sort_unstable();
    actual == wanted
}

impl DesktopSession {
    /// Mirrors DesktopMobileE2EEV2Session.create: expected-context
    /// gate first, then the exact-shape handshake validation, then
    /// the key schedule. `desktop_nonce` is injected for testability
    /// (upstream draws it from nacl.randomBytes).
    pub fn create(
        hello: &serde_json::Value,
        server_secret: &[u8; 32],
        expected_transport: &str,
        expected_relay_host_id: Option<&str>,
        desktop_nonce: [u8; 32],
    ) -> Option<DesktopSession> {
        let context = hello.get("context")?;
        if context.get("transport")?.as_str()? != expected_transport
            || context.get("relayHostId").and_then(|v| v.as_str()) != expected_relay_host_id
        {
            return None;
        }
        if !exact_keys(
            hello,
            &["type", "v", "clientPublicKeyB64", "clientNonceB64", "capabilities", "context"],
        )
            || hello.get("type")?.as_str()? != "e2ee_hello"
            || hello.get("v")?.as_u64()? != 2
        {
            return None;
        }
        let capabilities = hello.get("capabilities")?;
        if !exact_keys(capabilities, &["framing", "payloadKinds"])
            || capabilities.get("framing")?.as_array()?.iter().map(|v| v.as_u64()).collect::<Vec<_>>()
                != vec![Some(2)]
            || capabilities.get("payloadKinds")?.as_array()?.iter().map(|v| v.as_str()).collect::<Vec<_>>()
                != vec![Some("text"), Some("binary")]
        {
            return None;
        }
        let transport = context.get("transport")?.as_str()?;
        let relay_host_id = context.get("relayHostId").and_then(|v| v.as_str());
        let context_keys: &[&str] = if transport == "relay" {
            &["protocol", "initiator", "responder", "transport", "relayHostId"]
        } else {
            &["protocol", "initiator", "responder", "transport"]
        };
        if !exact_keys(context, context_keys)
            || context.get("protocol")?.as_str()? != "orca-mobile-e2ee"
            || context.get("initiator")?.as_str()? != "mobile"
            || context.get("responder")?.as_str()? != "desktop"
            || (transport != "direct" && transport != "relay")
        {
            return None;
        }
        if transport == "relay" {
            let id = relay_host_id?;
            let valid = id.len() == 16
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
            if !valid {
                return None;
            }
        }
        let client_public_key: [u8; 32] =
            *b64_decode_canonical(hello.get("clientPublicKeyB64")?.as_str()?, 32)?.first_chunk::<32>()?;
        let client_nonce: [u8; 32] =
            *b64_decode_canonical(hello.get("clientNonceB64")?.as_str()?, 32)?.first_chunk::<32>()?;
        let desktop_public_key = public_key_from_secret(server_secret);
        let ready = serde_json::json!({
            "type": "e2ee_ready",
            "v": 2,
            "desktopPublicKeyB64": b64_encode(&desktop_public_key),
            "clientNonceB64": hello.get("clientNonceB64")?.as_str()?,
            "desktopNonceB64": b64_encode(&desktop_nonce),
            "selection": { "framing": 2, "payloadKinds": ["text", "binary"] },
            "context": context.clone(),
        });
        let handshake = Handshake {
            client_public_key,
            client_nonce,
            desktop_public_key,
            desktop_nonce,
            transport: transport.to_string(),
            relay_host_id: relay_host_id.map(str::to_string),
        };
        let transcript = encode_transcript(&handshake);
        let shared_secret = derive_shared_key(server_secret, &client_public_key);
        let schedule = derive_key_schedule(&shared_secret, &transcript, &client_nonce, &desktop_nonce);
        Some(DesktopSession {
            ready,
            transcript_hash_b64: b64_encode(&schedule.transcript_hash),
            mobile_to_desktop_key: schedule.mobile_to_desktop_key,
            desktop_to_mobile_key: schedule.desktop_to_mobile_key,
            session_id: schedule.session_id,
            inbound_counter: 0,
            outbound_counter: 0,
        })
    }

    pub fn open_text(&mut self, frame_b64: &str) -> Option<String> {
        let frame = b64_decode_canonical_any(frame_b64)?;
        let plaintext = open_frame(
            &self.mobile_to_desktop_key,
            &self.session_id,
            Direction::MobileToDesktop,
            PayloadKind::Text,
            self.inbound_counter,
            &frame,
        )?;
        self.inbound_counter += 1;
        String::from_utf8(plaintext).ok()
    }

    pub fn seal_text(&mut self, plaintext: &str) -> String {
        let frame = seal_frame(
            &self.desktop_to_mobile_key,
            &self.session_id,
            Direction::DesktopToMobile,
            PayloadKind::Text,
            self.outbound_counter,
            plaintext.as_bytes(),
        );
        self.outbound_counter += 1;
        b64_encode(&frame)
    }

    pub fn open_binary(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let plaintext = open_frame(
            &self.mobile_to_desktop_key,
            &self.session_id,
            Direction::MobileToDesktop,
            PayloadKind::Binary,
            self.inbound_counter,
            frame,
        )?;
        self.inbound_counter += 1;
        Some(plaintext)
    }

    pub fn seal_binary(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let frame = seal_frame(
            &self.desktop_to_mobile_key,
            &self.session_id,
            Direction::DesktopToMobile,
            PayloadKind::Binary,
            self.outbound_counter,
            plaintext,
        );
        self.outbound_counter += 1;
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Upstream vector: mobile-e2ee-v2-fixtures.ts MOBILE_E2EE_V2_VECTOR.
    #[test]
    fn upstream_fixture_vector() {
        let handshake = Handshake {
            client_public_key: [1u8; 32],
            client_nonce: [2u8; 32],
            desktop_public_key: [3u8; 32],
            desktop_nonce: [4u8; 32],
            transport: "relay".to_string(),
            relay_host_id: Some("AbCdEf0123_-xyZ9".to_string()),
        };
        let transcript = encode_transcript(&handshake);
        assert_eq!(transcript.len(), 1347);
        let schedule = derive_key_schedule(
            &[5u8; 32],
            &transcript,
            &handshake.client_nonce,
            &handshake.desktop_nonce,
        );
        assert_eq!(
            hex(&schedule.transcript_hash),
            "ca6385f8bbf64a223fdd59587bfb67e2373891ce9e6d85ab41df8b7a20a168e3"
        );
        assert_eq!(
            hex(&schedule.mobile_to_desktop_key),
            "df17ff534df77fd3a30999f4e6200c8fcedefbb15d369301ca62c3cdfea9559a"
        );
        assert_eq!(
            hex(&schedule.desktop_to_mobile_key),
            "71365fcf8212a6d63caf909ee28de3c8f689682ef298a374136055e0ab1cde4a"
        );
        assert_eq!(
            hex(&schedule.session_id),
            "339ae1f2bdff63481857d2813c2f19dd1f5aa4824705d5e5daeb25dae7b9196e"
        );
    }

    /// Reference values computed with the fork's own tweetnacl
    /// (nacl.box.keyPair.fromSecretKey / nacl.box.before).
    #[test]
    fn box_before_matches_tweetnacl() {
        let secret_a = [0x0au8; 32];
        let secret_b = [0x0bu8; 32];
        let pub_a = public_key_from_secret(&secret_a);
        let pub_b = public_key_from_secret(&secret_b);
        assert_eq!(
            hex(&pub_a),
            "f77ff4b10788bfdca62ca0bb160d427cf5762d85f2b5cad6807ec9c3febbde09"
        );
        assert_eq!(
            hex(&pub_b),
            "73b2d8b76aa9b53660032bc8f5d8bee3a3ae4e3b3a7fd49ade81f7347a34aa68"
        );
        let expected = "e363947cf5ac235f5d719258f63cb77002231abd6503372f76b118fe1e81d157";
        assert_eq!(hex(&derive_shared_key(&secret_a, &pub_b)), expected);
        assert_eq!(hex(&derive_shared_key(&secret_b, &pub_a)), expected);
    }

    /// Reference signature computed with the fork's own tweetnacl
    /// (seed 32x0x0c, transcript hash 32x0x0d, purpose 'auth').
    #[test]
    fn device_proof_matches_tweetnacl() {
        let public_key = "C1E62bSSQBXKCQLtB5BE06xdvsIwbwaUjBDajrbjny0=";
        let proof = "flhr8Xo209Xf9XhP/9fm5F0BSmjnCI/ULS1k5gv2qNw90cAZ3rw9fa3nPSy/e9AaK9Q9LZJlo9ApNhv5st2FDQ==";
        let hash = "DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0=";
        assert!(verify_device_proof(public_key, proof, "auth", hash));
        assert!(!verify_device_proof(public_key, proof, "redeem", hash));
        assert!(!verify_device_proof(public_key, proof, "auth", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    /// Full handshake loop: a client built from the same primitives
    /// must be able to talk to the desktop session both ways.
    #[test]
    fn desktop_session_full_loop() {
        let server_secret = [0x21u8; 32];
        let client_secret = [0x22u8; 32];
        let client_nonce = [0x23u8; 32];
        let desktop_nonce = [0x24u8; 32];
        let client_public = public_key_from_secret(&client_secret);
        let hello = serde_json::json!({
            "type": "e2ee_hello",
            "v": 2,
            "clientPublicKeyB64": b64_encode(&client_public),
            "clientNonceB64": b64_encode(&client_nonce),
            "capabilities": { "framing": [2], "payloadKinds": ["text", "binary"] },
            "context": {
                "protocol": "orca-mobile-e2ee",
                "initiator": "mobile",
                "responder": "desktop",
                "transport": "direct"
            }
        });
        let mut session =
            DesktopSession::create(&hello, &server_secret, "direct", None, desktop_nonce)
                .expect("session");
        assert_eq!(
            session.ready.get("desktopPublicKeyB64").and_then(|v| v.as_str()),
            Some(b64_encode(&public_key_from_secret(&server_secret)).as_str())
        );
        assert_eq!(
            session.ready.get("clientNonceB64").and_then(|v| v.as_str()),
            Some(b64_encode(&client_nonce).as_str())
        );
        // Client side of the same handshake.
        let desktop_public = public_key_from_secret(&server_secret);
        let handshake = Handshake {
            client_public_key: client_public,
            client_nonce,
            desktop_public_key: desktop_public,
            desktop_nonce,
            transport: "direct".to_string(),
            relay_host_id: None,
        };
        let transcript = encode_transcript(&handshake);
        let shared = derive_shared_key(&client_secret, &desktop_public);
        let schedule = derive_key_schedule(&shared, &transcript, &client_nonce, &desktop_nonce);
        assert_eq!(session.transcript_hash_b64, b64_encode(&schedule.transcript_hash));
        // Client -> desktop, counter 0.
        let client_frame = seal_frame(
            &schedule.mobile_to_desktop_key,
            &schedule.session_id,
            Direction::MobileToDesktop,
            PayloadKind::Text,
            0,
            b"hello desktop",
        );
        assert_eq!(
            session.open_text(&b64_encode(&client_frame)).as_deref(),
            Some("hello desktop")
        );
        // Desktop -> client, counter 0.
        let reply_b64 = session.seal_text("hello client");
        let reply = b64_decode_canonical_any(&reply_b64).expect("frame b64");
        let opened = open_frame(
            &schedule.desktop_to_mobile_key,
            &schedule.session_id,
            Direction::DesktopToMobile,
            PayloadKind::Text,
            0,
            &reply,
        );
        assert_eq!(opened.as_deref(), Some(&b"hello client"[..]));
        // A hello for the wrong transport is refused.
        assert!(DesktopSession::create(&hello, &server_secret, "relay", Some("AbCdEf0123_-xyZ9"), desktop_nonce).is_none());
    }

    /// Upstream cases: mobile-e2ee-v2-framing.test.ts.
    #[test]
    fn framing_nonce_layout_and_round_trip() {
        let key = [7u8; 32];
        let session_id = [8u8; 32];
        let payload = b"e2ee-auth";
        let frame = seal_frame(&key, &session_id, Direction::MobileToDesktop, PayloadKind::Text, 0, payload);
        assert_eq!(
            hex(&frame[..24]),
            "080808080808080808080808020000000000000000000000"
        );
        let opened = open_frame(&key, &session_id, Direction::MobileToDesktop, PayloadKind::Text, 0, &frame);
        assert_eq!(opened.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn framing_rejects_replay_gap_reflection_kind_and_session() {
        let key = [7u8; 32];
        let session_id = [8u8; 32];
        let payload = b"e2ee-auth";
        let frame = seal_frame(&key, &session_id, Direction::MobileToDesktop, PayloadKind::Binary, 4, payload);
        let attempt = |direction: Direction, kind: PayloadKind, counter: u64, sid: &[u8; 32]| {
            open_frame(&key, sid, direction, kind, counter, &frame)
        };
        assert_eq!(
            attempt(Direction::MobileToDesktop, PayloadKind::Binary, 4, &session_id).as_deref(),
            Some(&payload[..])
        );
        assert!(attempt(Direction::MobileToDesktop, PayloadKind::Binary, 3, &session_id).is_none());
        assert!(attempt(Direction::MobileToDesktop, PayloadKind::Binary, 5, &session_id).is_none());
        assert!(attempt(Direction::DesktopToMobile, PayloadKind::Binary, 4, &session_id).is_none());
        assert!(attempt(Direction::MobileToDesktop, PayloadKind::Text, 4, &session_id).is_none());
        assert!(attempt(Direction::MobileToDesktop, PayloadKind::Binary, 4, &[9u8; 32]).is_none());
    }
}
