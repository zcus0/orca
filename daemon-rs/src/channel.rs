//! Per-socket E2EE v2 channel: a port of upstream's E2EEChannel
//! (`src/main/runtime/rpc/mobile/e2ee/e2ee-channel.ts`) restricted to
//! the v2 path, plus the auth classification from
//! `mobile-e2ee-auth-validation.ts`. Legacy v1 framing is refused
//! (4001, "E2EE v2 required"); the serve-mode web client uses v2.

use serde_json::Value;

use crate::e2ee::{b64_decode_canonical, verify_device_proof, DesktopSession};

/// One registry row from orca-devices.json (only the fields auth
/// needs; the file carries more).
#[derive(Clone)]
pub struct Device {
    pub device_id: String,
    pub token: Option<String>,
    /// A pending ticket-exchange replacement; accepted for sign-in
    /// until it retires the pairing token.
    pub exchange_token: Option<String>,
    pub device_public_key_b64: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum Action {
    SendText(String),
    Close(u16, String),
    Authenticated(String),
    RpcText(String),
    RpcBinary(Vec<u8>),
}

#[derive(PartialEq)]
enum State {
    AwaitingHello,
    AwaitingAuth,
    Ready,
}

pub struct Channel {
    state: State,
    session: Option<DesktopSession>,
    server_secret: [u8; 32],
    devices: Vec<Device>,
    consecutive_failures: u32,
    device_token: Option<String>,
    device_id: Option<String>,
}

const MAX_CONSECUTIVE_DECRYPT_FAILURES: u32 = 5;

impl Channel {
    pub fn new(server_secret: [u8; 32], devices: Vec<Device>) -> Channel {
        Channel {
            state: State::AwaitingHello,
            session: None,
            server_secret,
            devices,
            consecutive_failures: 0,
            device_token: None,
            device_id: None,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// The bearer token this socket authenticated with (None for
    /// device-key auth), for the per-request token check.
    pub fn device_token(&self) -> Option<&str> {
        self.device_token.as_deref()
    }

    /// The registry id this socket authenticated as.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// This connection's E2EE transcript hash (device-key proofs
    /// bind to it), once the handshake has run.
    pub fn transcript_hash_b64(&self) -> Option<String> {
        self.session.as_ref().map(|session| session.transcript_hash_b64.clone())
    }

    /// Seals an outbound text frame (RPC replies) with the session.
    pub fn seal_text(&mut self, plaintext: &str) -> Option<String> {
        self.session.as_mut().map(|session| session.seal_text(plaintext))
    }

    pub fn on_text(&mut self, raw: &str) -> Vec<Action> {
        if self.state == State::AwaitingHello {
            return self.handle_hello(raw);
        }
        let Some(session) = self.session.as_mut() else {
            return vec![];
        };
        match session.open_text(raw) {
            Some(plaintext) => {
                self.consecutive_failures = 0;
                if self.state == State::AwaitingAuth {
                    self.handle_auth(&plaintext)
                } else {
                    vec![Action::RpcText(plaintext)]
                }
            }
            None => self.track_decrypt_failure(),
        }
    }

    pub fn on_binary(&mut self, raw: &[u8]) -> Vec<Action> {
        if self.state == State::AwaitingHello {
            return vec![Action::Close(4001, "Invalid handshake message".to_string())];
        }
        let Some(session) = self.session.as_mut() else {
            return vec![];
        };
        match session.open_binary(raw) {
            Some(plaintext) => {
                self.consecutive_failures = 0;
                if self.state == State::AwaitingAuth {
                    vec![Action::Close(
                        4001,
                        "Invalid binary message before authentication".to_string(),
                    )]
                } else {
                    vec![Action::RpcBinary(plaintext)]
                }
            }
            None => self.track_decrypt_failure(),
        }
    }

    fn handle_hello(&mut self, raw: &str) -> Vec<Action> {
        let parsed: Value = match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(_) => return vec![Action::Close(4001, "Invalid handshake message".to_string())],
        };
        if !parsed.is_object() {
            return vec![Action::Close(4001, "Invalid handshake message".to_string())];
        }
        if parsed.get("type").and_then(|v| v.as_str()) == Some("e2ee_hello")
            && parsed.get("v").and_then(|v| v.as_u64()) == Some(2)
        {
            let mut desktop_nonce = [0u8; 32];
            getrandom::fill(&mut desktop_nonce).expect("OS randomness");
            match DesktopSession::create(&parsed, &self.server_secret, "direct", None, desktop_nonce) {
                Some(session) => {
                    let ready = serde_json::to_string(&session.ready)
                        .expect("ready is serializable");
                    self.session = Some(session);
                    self.state = State::AwaitingAuth;
                    vec![Action::SendText(ready)]
                }
                None => vec![Action::Close(4001, "Invalid e2ee_hello v2".to_string())],
            }
        } else {
            vec![Action::Close(4001, "E2EE v2 required".to_string())]
        }
    }

    fn track_decrypt_failure(&mut self) -> Vec<Action> {
        if self.state == State::AwaitingAuth {
            return vec![Action::Close(4001, "Unauthorized".to_string())];
        }
        self.consecutive_failures += 1;
        if self.consecutive_failures >= MAX_CONSECUTIVE_DECRYPT_FAILURES {
            return vec![Action::Close(4003, "Too many decryption failures".to_string())];
        }
        vec![]
    }

    /// authenticateMobileE2EE for a direct v2 socket: token auth
    /// (capabilities allowed) or device-key proof auth.
    fn handle_auth(&mut self, plaintext: &str) -> Vec<Action> {
        let session = self.session.as_mut().expect("session in auth");
        let failure = |session: &mut DesktopSession, code: &str, device_id: Option<&str>| {
            let mut error = serde_json::json!({ "code": code });
            if let Some(id) = device_id {
                error["deviceId"] = Value::String(id.to_string());
            }
            let sealed = session
                .seal_text(&serde_json::json!({ "type": "e2ee_error", "error": error }).to_string());
            let reason = match code {
                "unauthorized" | "device_revoked" => "Unauthorized",
                "registry_unavailable" => "Device registry unavailable",
                _ => "Invalid e2ee_auth",
            };
            vec![Action::SendText(sealed), Action::Close(4001, reason.to_string())]
        };
        let parsed: Value = match serde_json::from_str::<Value>(plaintext) {
            Ok(value) if value.is_object() => value,
            _ => return failure(session, "bad_auth", None),
        };
        if parsed.get("type").and_then(|v| v.as_str()) != Some("e2ee_auth")
            || parsed.get("v").and_then(|v| v.as_u64()) != Some(2)
            || parsed.get("transcriptHashB64").and_then(|v| v.as_str())
                != Some(session.transcript_hash_b64.as_str())
        {
            return failure(session, "bad_auth", None);
        }
        let mut keys: Vec<&str> = parsed
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let token_shape = {
            let without_caps: Vec<&str> =
                keys.iter().copied().filter(|k| *k != "clientCapabilities").collect();
            without_caps == ["deviceToken", "transcriptHashB64", "type", "v"]
        };
        if token_shape {
            let token = parsed.get("deviceToken").and_then(|v| v.as_str()).unwrap_or("");
            if !token.is_empty() {
                if let Some(device) = self.devices.iter().find(|d| {
                    d.token.as_deref() == Some(token) || d.exchange_token.as_deref() == Some(token)
                }) {
                    let device_id = device.device_id.clone();
                    return self.auth_success(device_id, Some(token.to_string()));
                }
            }
            return failure(session, "unauthorized", None);
        }
        let rest: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|k| !["type", "v", "transcriptHashB64"].contains(k))
            .collect();
        let device_key_shape = rest
            .iter()
            .all(|k| ["clientCapabilities", "deviceId", "deviceProofB64"].contains(k))
            && parsed
                .get("deviceId")
                .and_then(|v| v.as_str())
                .is_some_and(|id| !id.is_empty() && id.len() <= 128)
            && parsed
                .get("deviceProofB64")
                .and_then(|v| v.as_str())
                .is_some_and(|proof| b64_decode_canonical(proof, 64).is_some());
        if device_key_shape {
            let device_id = parsed.get("deviceId").and_then(|v| v.as_str()).expect("checked");
            let proof = parsed.get("deviceProofB64").and_then(|v| v.as_str()).expect("checked");
            let Some(device) = self.devices.iter().find(|d| d.device_id == device_id) else {
                return failure(session, "device_revoked", Some(device_id));
            };
            let Some(public_key) = device.device_public_key_b64.clone() else {
                return failure(session, "bad_auth", None);
            };
            if verify_device_proof(&public_key, proof, "auth", &session.transcript_hash_b64) {
                let device_id = device_id.to_string();
                return self.auth_success(device_id, None);
            }
            return failure(session, "bad_proof", None);
        }
        failure(session, "bad_auth", None)
    }

    fn auth_success(&mut self, device_id: String, device_token: Option<String>) -> Vec<Action> {
        self.state = State::Ready;
        self.device_token = device_token;
        self.device_id = Some(device_id.clone());
        let session = self.session.as_mut().expect("session");
        let sealed = session.seal_text(
            &serde_json::json!({
                "type": "e2ee_authenticated",
                "v": 2,
                "transcriptHashB64": session.transcript_hash_b64,
            })
            .to_string(),
        );
        vec![Action::Authenticated(device_id), Action::SendText(sealed)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::{
        b64_encode, derive_key_schedule, derive_shared_key, encode_transcript,
        open_frame, public_key_from_secret, seal_frame, Direction, Handshake,
        PayloadKind,
    };

    const SERVER_SECRET: [u8; 32] = [0x31u8; 32];
    const CLIENT_SECRET: [u8; 32] = [0x32u8; 32];
    const CLIENT_NONCE: [u8; 32] = [0x33u8; 32];

    struct ClientSide {
        schedule: crate::e2ee::KeySchedule,
        transcript_hash_b64: String,
        counter_out: u64,
        counter_in: u64,
    }

    impl ClientSide {
        fn seal_text(&mut self, plaintext: &str) -> String {
            let frame = seal_frame(
                &self.schedule.mobile_to_desktop_key,
                &self.schedule.session_id,
                Direction::MobileToDesktop,
                PayloadKind::Text,
                self.counter_out,
                plaintext.as_bytes(),
            );
            self.counter_out += 1;
            b64_encode(&frame)
        }
        fn open_text(&mut self, frame_b64: &str) -> Option<String> {
            let frame = crate::e2ee::b64_decode_canonical_any(frame_b64)?;
            let plain = open_frame(
                &self.schedule.desktop_to_mobile_key,
                &self.schedule.session_id,
                Direction::DesktopToMobile,
                PayloadKind::Text,
                self.counter_in,
                &frame,
            )?;
            self.counter_in += 1;
            String::from_utf8(plain).ok()
        }
    }

    fn hello_json() -> String {
        serde_json::json!({
            "type": "e2ee_hello",
            "v": 2,
            "clientPublicKeyB64": b64_encode(&public_key_from_secret(&CLIENT_SECRET)),
            "clientNonceB64": b64_encode(&CLIENT_NONCE),
            "capabilities": { "framing": [2], "payloadKinds": ["text", "binary"] },
            "context": {
                "protocol": "orca-mobile-e2ee",
                "initiator": "mobile",
                "responder": "desktop",
                "transport": "direct"
            }
        })
        .to_string()
    }

    /// Runs the hello and derives the client-side schedule from the
    /// ready the channel produced (the desktop nonce comes from it,
    /// exactly like the real client).
    fn handshake(channel: &mut Channel) -> ClientSide {
        let actions = channel.on_text(&hello_json());
        let ready_text = match &actions[0] {
            Action::SendText(text) => text.clone(),
            other => panic!("expected ready, got {other:?}"),
        };
        let ready: Value = serde_json::from_str(&ready_text).unwrap();
        let desktop_nonce: [u8; 32] = *crate::e2ee::b64_decode_canonical(
            ready.get("desktopNonceB64").and_then(|v| v.as_str()).unwrap(),
            32,
        )
        .unwrap()
        .first_chunk::<32>()
        .unwrap();
        let handshake = Handshake {
            client_public_key: public_key_from_secret(&CLIENT_SECRET),
            client_nonce: CLIENT_NONCE,
            desktop_public_key: public_key_from_secret(&SERVER_SECRET),
            desktop_nonce,
            transport: "direct".to_string(),
            relay_host_id: None,
        };
        let transcript = encode_transcript(&handshake);
        let shared = derive_shared_key(&CLIENT_SECRET, &handshake.desktop_public_key);
        let schedule = derive_key_schedule(&shared, &transcript, &CLIENT_NONCE, &desktop_nonce);
        ClientSide {
            transcript_hash_b64: b64_encode(&schedule.transcript_hash),
            schedule,
            counter_out: 0,
            counter_in: 0,
        }
    }

    fn token_channel() -> Channel {
        Channel::new(
            SERVER_SECRET,
            vec![Device {
                device_id: "dev-1".to_string(),
                token: Some("tok-abc".to_string()),
                exchange_token: None,
                device_public_key_b64: None,
            }],
        )
    }

    #[test]
    fn token_auth_full_flow() {
        let mut channel = token_channel();
        let mut client = handshake(&mut channel);
        let auth = serde_json::json!({
            "type": "e2ee_auth",
            "v": 2,
            "transcriptHashB64": client.transcript_hash_b64,
            "deviceToken": "tok-abc"
        })
        .to_string();
        let actions = channel.on_text(&client.seal_text(&auth));
        assert_eq!(actions[0], Action::Authenticated("dev-1".to_string()));
        let sealed = match &actions[1] {
            Action::SendText(text) => text.clone(),
            other => panic!("expected sealed authenticated, got {other:?}"),
        };
        let opened: Value = serde_json::from_str(&client.open_text(&sealed).unwrap()).unwrap();
        assert_eq!(opened.get("type").and_then(|v| v.as_str()), Some("e2ee_authenticated"));
        assert!(channel.is_ready());
        // Post-auth text reaches the RPC layer decrypted.
        let rpc = client.seal_text("{\"method\":\"ping\"}");
        assert_eq!(channel.on_text(&rpc), vec![Action::RpcText("{\"method\":\"ping\"}".to_string())]);
    }

    #[test]
    fn wrong_token_gets_sealed_error_and_close() {
        let mut channel = token_channel();
        let mut client = handshake(&mut channel);
        let auth = serde_json::json!({
            "type": "e2ee_auth",
            "v": 2,
            "transcriptHashB64": client.transcript_hash_b64,
            "deviceToken": "tok-WRONG"
        })
        .to_string();
        let actions = channel.on_text(&client.seal_text(&auth));
        let sealed = match &actions[0] {
            Action::SendText(text) => text.clone(),
            other => panic!("expected sealed error, got {other:?}"),
        };
        let opened: Value = serde_json::from_str(&client.open_text(&sealed).unwrap()).unwrap();
        assert_eq!(opened.get("type").and_then(|v| v.as_str()), Some("e2ee_error"));
        assert_eq!(
            opened.pointer("/error/code").and_then(|v| v.as_str()),
            Some("unauthorized")
        );
        assert_eq!(actions[1], Action::Close(4001, "Unauthorized".to_string()));
    }

    #[test]
    fn device_key_auth_full_flow() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x0cu8; 32]);
        let device_public_b64 = b64_encode(signing.verifying_key().as_bytes());
        let mut channel = Channel::new(
            SERVER_SECRET,
            vec![Device {
                device_id: "dev-key-1".to_string(),
                token: None,
                exchange_token: None,
                device_public_key_b64: Some(device_public_b64),
            }],
        );
        let mut client = handshake(&mut channel);
        let transcript_hash =
            crate::e2ee::b64_decode_canonical(&client.transcript_hash_b64, 32).unwrap();
        let mut message = Vec::new();
        message.extend_from_slice(b"orca-device-proof/v1\0auth\0");
        message.extend_from_slice(&transcript_hash);
        let proof_b64 = b64_encode(&signing.sign(&message).to_bytes());
        let auth = serde_json::json!({
            "type": "e2ee_auth",
            "v": 2,
            "transcriptHashB64": client.transcript_hash_b64,
            "deviceId": "dev-key-1",
            "deviceProofB64": proof_b64
        })
        .to_string();
        let actions = channel.on_text(&client.seal_text(&auth));
        assert_eq!(actions[0], Action::Authenticated("dev-key-1".to_string()));
        assert!(channel.is_ready());
    }
}
