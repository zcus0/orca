//! Minimal RPC dispatch (Fase 3 M3): the request frame
//! `{id, deviceToken, method, params}` and the response envelope
//! `{id, ok, result|error, _meta:{runtimeId}}` from upstream's
//! runtime-rpc-envelope. Unknown methods answer method_not_found
//! exactly like upstream's admission prologue, so clients fall
//! back cleanly. Implemented surface: the bootstrap reads
//! (host.platform, host.peerDesktops, status.get), the session
//! inventory stubs (filled by M4/M5), and the pairing writes
//! (exchangeTicket, registerDeviceKey).

use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::e2ee::b64_decode_canonical;
use crate::registry::Registry;

/// Per-socket facts a handler may need, captured at dispatch time.
pub struct Ctx {
    pub device_id: Option<String>,
    pub device_token: Option<String>,
    pub transcript_hash_b64: Option<String>,
}

/// Host capabilities daemon-rs honestly serves today.
const CAPABILITIES: [&str; 4] = [
    "pairing.device-key.v1",
    "pairing.device-key-ephemeral.v1",
    "pairing.e2ee-v2-token-capabilities.v1",
    "pairing.ticket-exchange.v1",
];

const RUNTIME_PROTOCOL_VERSION: u64 = 3;
const MIN_COMPATIBLE_CLIENT_VERSION: u64 = 2;

pub struct Rpc {
    runtime_id: String,
    subscriptions: Vec<String>,
    registry: Arc<Mutex<Registry>>,
    machine_name: String,
}

impl Rpc {
    pub fn new(runtime_id: String, registry: Arc<Mutex<Registry>>) -> Rpc {
        Rpc {
            runtime_id,
            subscriptions: Vec::new(),
            registry,
            machine_name: machine_name(),
        }
    }

    /// Handles one decrypted request text. Returns the response
    /// text to seal and send, or None for frames that take no
    /// reply (keepalives, id-less frames).
    pub fn handle(&mut self, plaintext: &str, ctx: &Ctx) -> Option<String> {
        let request: Value = serde_json::from_str(plaintext).ok()?;
        if request.get("_keepalive").and_then(|v| v.as_bool()) == Some(true) {
            return None;
        }
        let id = request.get("id")?.as_str()?.to_string();
        let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        if let Some(token) = request.get("deviceToken").and_then(|v| v.as_str()) {
            if ctx.device_token.as_deref() != Some(token) {
                return Some(self.failure(&id, "unauthorized", "Device token mismatch"));
            }
        }
        let outcome: Result<Value, String> = match method {
            "host.platform" => Ok(json!({ "platform": node_platform() })),
            "host.peerDesktops" => Ok(json!({ "peers": [] })),
            "status.get" => Ok(self.status(&params, ctx)),
            "runtime.clientCapabilities.update" => Ok(Value::Null),
            "runtime.clientEvents.subscribe" => {
                self.subscriptions.push(id.clone());
                Ok(Value::Null)
            }
            "runtime.clientEvents.unsubscribe" => Ok(Value::Null),
            "session.tabs.listAll" => Ok(json!({ "snapshots": [] })),
            "session.tabs.subscribeAll" => {
                self.subscriptions.push(id.clone());
                Ok(json!({ "snapshots": [] }))
            }
            "session.tabs.unsubscribeAll" => Ok(Value::Null),
            "pairing.exchangeTicket" => self.exchange_ticket(&params, ctx),
            "pairing.registerDeviceKey" => self.register_device_key(&params, ctx),
            _ => {
                return Some(self.failure(
                    &id,
                    "method_not_found",
                    &format!("Unknown method: {method}"),
                ))
            }
        };
        Some(match outcome {
            Ok(result) => self.success(&id, result),
            Err(code) => self.failure(&id, &code, &code),
        })
    }

    fn status(&self, params: &Value, ctx: &Ctx) -> Value {
        if params.get("probe").and_then(|v| v.as_bool()) == Some(true) {
            return json!({ "runtimeId": self.runtime_id });
        }
        let mut status = json!({
            "runtimeId": self.runtime_id,
            "rendererGraphEpoch": 0,
            "graphStatus": "ready",
            "authoritativeWindowId": Value::Null,
            "liveTabCount": 0,
            "liveLeafCount": 0,
            "runtimeProtocolVersion": RUNTIME_PROTOCOL_VERSION,
            "minCompatibleRuntimeClientVersion": MIN_COMPATIBLE_CLIENT_VERSION,
            "capabilities": CAPABILITIES,
            "hostPlatform": node_platform(),
            "machineName": self.machine_name,
            "appVersion": env!("CARGO_PKG_VERSION"),
            "protocolVersion": RUNTIME_PROTOCOL_VERSION,
            "minCompatibleMobileVersion": MIN_COMPATIBLE_CLIENT_VERSION,
        });
        if let Some(device_id) = &ctx.device_id {
            status
                .as_object_mut()
                .unwrap()
                .insert("pairedDeviceId".to_string(), json!(device_id));
        }
        status
    }

    fn exchange_ticket(&self, params: &Value, ctx: &Ctx) -> Result<Value, String> {
        let new_token = params
            .get("deviceToken")
            .and_then(|v| v.as_str())
            .filter(|token| is_exchange_token(token))
            .ok_or_else(|| "invalid_argument".to_string())?;
        let device_id = ctx.device_id.as_deref().ok_or("unauthorized")?;
        let presented = ctx.device_token.as_deref().unwrap_or("");
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        let device_id = registry.exchange_ticket(device_id, presented, new_token)?;
        Ok(json!({ "deviceId": device_id }))
    }

    fn register_device_key(&self, params: &Value, ctx: &Ctx) -> Result<Value, String> {
        let public_key = params
            .get("devicePublicKeyB64")
            .and_then(|v| v.as_str())
            .filter(|key| b64_decode_canonical(key, 32).is_some())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let proof = params
            .get("deviceProofB64")
            .and_then(|v| v.as_str())
            .filter(|sig| b64_decode_canonical(sig, 64).is_some())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let device_id = ctx.device_id.as_deref().ok_or("unauthorized")?;
        let label = params.get("deviceLabel").and_then(|v| v.as_str());
        let ephemeral = params.get("ephemeral").and_then(|v| v.as_bool()) == Some(true);
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        let (new_id, revision) = registry.register_device_key(
            device_id,
            public_key,
            proof,
            label,
            ephemeral,
            ctx.transcript_hash_b64.as_deref(),
        )?;
        Ok(json!({ "deviceId": new_id, "credentialRevision": revision }))
    }

    fn success(&self, id: &str, result: Value) -> String {
        json!({
            "id": id,
            "ok": true,
            "result": result,
            "_meta": { "runtimeId": self.runtime_id },
        })
        .to_string()
    }

    fn failure(&self, id: &str, code: &str, message: &str) -> String {
        json!({
            "id": id,
            "ok": false,
            "error": { "code": code, "message": message },
            "_meta": { "runtimeId": self.runtime_id },
        })
        .to_string()
    }
}

/// Client-generated exchange tokens: 48–128 lowercase hex chars.
fn is_exchange_token(token: &str) -> bool {
    (48..=128).contains(&token.len())
        && token.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// process.platform equivalents for the hosts daemon-rs runs on.
fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

fn machine_name() -> String {
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if !name.is_empty() {
            return name;
        }
    }
    if let Ok(text) = std::fs::read_to_string("/etc/hostname") {
        let name = text.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    "orca-rs".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc() -> Rpc {
        let dir = std::env::temp_dir().join(format!("daemon-rs-rpc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Rpc::new(
            "runtime-test".to_string(),
            Arc::new(Mutex::new(Registry::load(dir))),
        )
    }

    fn anon() -> Ctx {
        Ctx { device_id: None, device_token: None, transcript_hash_b64: None }
    }

    #[test]
    fn platform_and_unknown_method() {
        let mut rpc = rpc();
        let response = rpc
            .handle(r#"{"id":"1","method":"host.platform","params":null}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["_meta"]["runtimeId"], "runtime-test");
        assert!(parsed["result"]["platform"].is_string());
        let response = rpc
            .handle(r#"{"id":"2","method":"nope.nope","params":null}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"]["code"], "method_not_found");
        assert_eq!(parsed["error"]["message"], "Unknown method: nope.nope");
    }

    #[test]
    fn status_probe_and_full() {
        let mut rpc = rpc();
        let response = rpc
            .handle(r#"{"id":"5","method":"status.get","params":{"probe":true}}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"], json!({ "runtimeId": "runtime-test" }));
        let ctx = Ctx {
            device_id: Some("dev-9".to_string()),
            device_token: None,
            transcript_hash_b64: None,
        };
        let response = rpc.handle(r#"{"id":"6","method":"status.get","params":{}}"#, &ctx).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["graphStatus"], "ready");
        assert_eq!(parsed["result"]["pairedDeviceId"], "dev-9");
        assert!(parsed["result"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "pairing.ticket-exchange.v1"));
    }

    #[test]
    fn empty_inventory_and_keepalive() {
        let mut rpc = rpc();
        let response = rpc
            .handle(r#"{"id":"3","method":"session.tabs.listAll","params":null}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"], json!({ "snapshots": [] }));
        assert!(rpc.handle(r#"{"_keepalive":true}"#, &anon()).is_none());
    }

    #[test]
    fn token_mismatch_is_unauthorized() {
        let mut rpc = rpc();
        let ctx = Ctx {
            device_id: None,
            device_token: Some("right".to_string()),
            transcript_hash_b64: None,
        };
        let response = rpc
            .handle(
                r#"{"id":"4","deviceToken":"wrong","method":"host.platform","params":null}"#,
                &ctx,
            )
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["error"]["code"], "unauthorized");
    }
}
