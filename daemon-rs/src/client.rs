//! Client half of the E2EE v2 pairing protocol — the mirror of
//! DesktopSession in e2ee.rs, for embedding in shells that talk
//! to a real orcad serve (the app-shell variant). Same wire
//! contract as the Node E2E client: hello → ready → sealed
//! token auth → sealed RPC text frames.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::e2ee::{
    b64_decode_canonical, b64_encode, derive_key_schedule, derive_shared_key, encode_transcript,
    open_frame, public_key_from_secret, seal_frame, Direction, Handshake, PayloadKind,
};

pub struct PairingOffer {
    pub endpoint: String,
    pub device_token: String,
    pub host_public_key: [u8; 32],
}

/// The offer rides in the serve readiness line / pairing URL as
/// JSON with base64url-or-standard fields; only the three the
/// client needs are read here.
pub fn parse_offer(value: &serde_json::Value) -> Option<PairingOffer> {
    let endpoint = value.get("endpoint")?.as_str()?.to_string();
    let device_token = value.get("deviceToken")?.as_str()?.to_string();
    let public_b64 = value.get("publicKeyB64")?.as_str()?;
    let host_public_key: [u8; 32] = b64_decode_canonical(public_b64, 32)?.try_into().ok()?;
    Some(PairingOffer { endpoint, device_token, host_public_key })
}

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

pub struct RuntimeClient {
    ws: Ws,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    session_id: [u8; 32],
    out_counter: u64,
    in_counter: u64,
    next_id: u64,
    device_token: String,
}

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS RNG must be available");
    bytes
}

impl RuntimeClient {
    pub async fn connect(offer: &PairingOffer) -> Result<Self, String> {
        let (mut ws, _) = tokio_tungstenite::connect_async(&offer.endpoint)
            .await
            .map_err(|e| format!("ws connect: {e}"))?;
        let secret = random_32();
        let client_public_key = public_key_from_secret(&secret);
        let client_nonce = random_32();
        let hello = serde_json::json!({
            "type": "e2ee_hello",
            "v": 2,
            "clientPublicKeyB64": b64_encode(&client_public_key),
            "clientNonceB64": b64_encode(&client_nonce),
            "capabilities": { "framing": [2], "payloadKinds": ["text", "binary"] },
            "context": {
                "protocol": "orca-mobile-e2ee",
                "initiator": "mobile",
                "responder": "desktop",
                "transport": "direct"
            }
        });
        ws.send(Message::Text(hello.to_string().into()))
            .await
            .map_err(|e| format!("hello send: {e}"))?;
        let ready_msg = ws
            .next()
            .await
            .ok_or("connection closed before ready")?
            .map_err(|e| format!("ready recv: {e}"))?;
        let ready: serde_json::Value =
            serde_json::from_str(&ready_msg.to_text().map_err(|_| "ready not text")?)
                .map_err(|e| format!("ready parse: {e}"))?;
        if ready.get("type").and_then(|t| t.as_str()) != Some("e2ee_ready") {
            return Err(format!("unexpected handshake reply: {ready}"));
        }
        let desktop_nonce: [u8; 32] = b64_decode_canonical(
            ready
                .get("desktopNonceB64")
                .and_then(|v| v.as_str())
                .ok_or("ready missing desktopNonceB64")?,
            32,
        )
        .ok_or("desktop nonce not canonical base64")?
        .try_into()
        .map_err(|_| "desktop nonce length")?;
        let handshake = Handshake {
            client_public_key,
            client_nonce,
            desktop_public_key: offer.host_public_key,
            desktop_nonce,
            transport: "direct".to_string(),
            relay_host_id: None,
        };
        let transcript = encode_transcript(&handshake);
        let shared = derive_shared_key(&secret, &offer.host_public_key);
        let schedule =
            derive_key_schedule(&shared, &transcript, &client_nonce, &desktop_nonce);
        let mut client = Self {
            ws,
            send_key: schedule.mobile_to_desktop_key,
            recv_key: schedule.desktop_to_mobile_key,
            session_id: schedule.session_id,
            out_counter: 0,
            in_counter: 0,
            next_id: 0,
            device_token: offer.device_token.clone(),
        };
        let auth = serde_json::json!({
            "type": "e2ee_auth",
            "v": 2,
            "transcriptHashB64": b64_encode(&schedule.transcript_hash),
            "deviceToken": offer.device_token,
        });
        client.send_text(&auth.to_string()).await?;
        let reply = client.recv_text().await?;
        let reply_json: serde_json::Value =
            serde_json::from_str(&reply).map_err(|e| format!("auth reply parse: {e}"))?;
        if reply_json.get("type").and_then(|t| t.as_str()) != Some("e2ee_authenticated") {
            return Err(format!("auth refused: {reply_json}"));
        }
        Ok(client)
    }

    async fn send_text(&mut self, plaintext: &str) -> Result<(), String> {
        let frame = seal_frame(
            &self.send_key,
            &self.session_id,
            Direction::MobileToDesktop,
            PayloadKind::Text,
            self.out_counter,
            plaintext.as_bytes(),
        );
        self.out_counter += 1;
        self.ws
            .send(Message::Text(b64_encode(&frame).into()))
            .await
            .map_err(|e| format!("frame send: {e}"))
    }

    async fn recv_text(&mut self) -> Result<String, String> {
        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or("connection closed")?
                .map_err(|e| format!("frame recv: {e}"))?;
            let text = match msg {
                Message::Text(text) => text,
                Message::Ping(payload) => {
                    self.ws
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|e| format!("pong: {e}"))?;
                    continue;
                }
                _ => continue,
            };
            let frame = crate::e2ee::b64_decode_canonical_any(&text)
                .ok_or("frame not base64")?;
            let plaintext = open_frame(
                &self.recv_key,
                &self.session_id,
                Direction::DesktopToMobile,
                PayloadKind::Text,
                self.in_counter,
                &frame,
            )
            .ok_or("frame open failed")?;
            self.in_counter += 1;
            return String::from_utf8(plaintext).map_err(|e| format!("frame utf8: {e}"));
        }
    }

    /// One request/response round trip. Server-pushed frames
    /// (events, keepalives) are skipped, not surfaced — the
    /// shell's subscription bridge is a later slice.
    pub async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.next_id += 1;
        let id = self.next_id.to_string();
        let request = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
            "deviceToken": self.device_token,
        });
        self.send_text(&request.to_string()).await?;
        loop {
            let text = self.recv_text().await?;
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("rpc parse: {e}"))?;
            if value.get("_keepalive").and_then(|k| k.as_bool()) == Some(true) {
                continue;
            }
            if value.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
                return Ok(value);
            }
        }
    }
}
