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
use std::path::PathBuf;
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
    profile_dir: PathBuf,
    pty: Arc<Mutex<crate::pty::PtyManager>>,
    graph: Arc<Mutex<crate::graph::Graph>>,
}

impl Rpc {
    pub fn new(
        runtime_id: String,
        registry: Arc<Mutex<Registry>>,
        profile_dir: PathBuf,
        pty: Arc<Mutex<crate::pty::PtyManager>>,
        graph: Arc<Mutex<crate::graph::Graph>>,
    ) -> Rpc {
        Rpc {
            runtime_id,
            subscriptions: Vec::new(),
            registry,
            machine_name: machine_name(),
            profile_dir,
            pty,
            graph,
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
            "repo.list" => Ok(json!({ "repos": self.repo_list() })),
            "status.get" => Ok(self.status(&params, ctx)),
            "runtime.clientCapabilities.update" => Ok(Value::Null),
            "runtime.clientEvents.subscribe" => {
                self.subscriptions.push(id.clone());
                Ok(Value::Null)
            }
            "runtime.clientEvents.unsubscribe" => Ok(Value::Null),
            "session.tabs.listAll" => Ok(self.tabs_inventory()),
            "session.tabs.subscribeAll" => {
                self.subscriptions.push(id.clone());
                Ok(self.tabs_inventory())
            }
            "session.tabs.list" => Ok(self.tabs_snapshot(&params)),
            "session.tabs.subscribe" => {
                self.subscriptions.push(id.clone());
                let mut snapshot = self.tabs_snapshot(&params);
                if let Some(object) = snapshot.as_object_mut() {
                    object.insert("type".to_string(), json!("snapshot"));
                }
                Ok(snapshot)
            }
            "session.tabs.createTerminal" => self.tabs_create_terminal(&params),
            "session.tabs.close" => self.tabs_close(&params),
            "session.tabs.unsubscribeAll" => Ok(Value::Null),
            "pairing.exchangeTicket" => self.exchange_ticket(&params, ctx),
            "pairing.registerDeviceKey" => self.register_device_key(&params, ctx),
            "terminal.create" => self.terminal_create(&params),
            "terminal.multiplex" => Ok(json!({ "type": "ready" })),
            "terminal.send" => self.terminal_send(&params),
            "terminal.read" => self.terminal_read(&params),
            "terminal.list" => Ok(self.terminal_list(&params)),
            "terminal.close" => self.terminal_close(&params),
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

    /// The workspace catalog lives in the profile state store as a
    /// bare JSON array under the `repos` domain; serve it verbatim,
    /// exactly as orcad does. Absent store/domain = no repos yet.
    fn repo_list(&self) -> Value {
        crate::profile_state::read_domain(&self.profile_dir, "repos")
            .filter(|payload| payload.is_array())
            .unwrap_or_else(|| json!([]))
    }

    // --- Terminals (M4 slice 2) --------------------------------
    // The unary terminal.* surface (CLI/automation consumers).
    // The web client's session-graph + multiplex streaming is
    // slice 3. Handles are daemon-rs session ids; the Terminal
    // object carries the fields daemon-rs can honestly fill
    // without the graph (handle, ptyId, cwd, title, state).

    fn terminal_create(&self, params: &Value) -> Result<Value, String> {
        let handle = self.spawn_terminal(params)?;
        let pty = self.pty.lock().map_err(|_| "pty_unavailable")?;
        Ok(json!({ "terminal": terminal_json(&handle, &pty) }))
    }

    /// Spawns a PTY for the shared create params (worktree /
    /// cwd / command / env / title) and returns its handle.
    /// Used by terminal.create and session.tabs.createTerminal.
    fn spawn_terminal(&self, params: &Value) -> Result<String, String> {
        let worktree = params.get("worktree").and_then(|v| v.as_str());
        let cwd = params
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| self.resolve_worktree_path(worktree))
            .or_else(|| std::env::var("HOME").ok());
        let env: Vec<(String, String)> = params
            .get("env")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let handle = format!("term-{}", crate::registry::uuid());
        let mut pty = self.pty.lock().map_err(|_| "pty_unavailable")?;
        pty.spawn(
            &handle,
            80,
            24,
            cwd.as_deref(),
            params.get("command").and_then(|v| v.as_str()),
            if env.is_empty() { None } else { Some(&env) },
        )?;
        pty.set_meta(
            &handle,
            crate::pty::SessionMeta {
                worktree: worktree.map(str::to_string),
                cwd: cwd.clone(),
                title: params.get("title").and_then(|v| v.as_str()).map(str::to_string),
                created_at_ms: now_ms(),
            },
        );
        Ok(handle)
    }

    // --- Session graph (M4 slice 3b step 4) -------------------
    // The flat graph subset in crate::graph: createTerminal
    // spawns a PTY and publishes a terminal tab; list/listAll
    // serve the snapshots panes render from; close retires
    // both the tab and its PTY.

    /// The graph key for a worktree selector: the resolved repo
    /// path when the selector names a catalog repo, else the
    /// selector verbatim (both sides resolve identically).
    fn worktree_key(&self, params: &Value) -> Option<String> {
        let selector = params.get("worktree").and_then(|v| v.as_str())?;
        Some(self.resolve_worktree_path(Some(selector)).unwrap_or_else(|| selector.to_string()))
    }

    fn tabs_inventory(&self) -> Value {
        let Ok(graph) = self.graph.lock() else {
            return json!({ "snapshots": [] });
        };
        graph.inventory()
    }

    fn tabs_snapshot(&self, params: &Value) -> Value {
        let Some(key) = self.worktree_key(params) else {
            return json!({
                "worktree": "",
                "publicationEpoch": "none",
                "snapshotVersion": 0,
                "activeGroupId": Value::Null,
                "activeTabId": Value::Null,
                "activeTabType": Value::Null,
                "tabs": [],
            });
        };
        let Ok(graph) = self.graph.lock() else {
            return json!({ "snapshots": [] });
        };
        graph.snapshot(&key)
    }

    fn tabs_create_terminal(&self, params: &Value) -> Result<Value, String> {
        let Some(key) = self.worktree_key(params) else {
            return Err("invalid_argument".to_string());
        };
        let handle = self.spawn_terminal(params)?;
        let title = params
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Terminal")
            .to_string();
        let cwd = params
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| self.resolve_worktree_path(params.get("worktree").and_then(|v| v.as_str())));
        let mut graph = self.graph.lock().map_err(|_| "graph_unavailable")?;
        let (_tab_id, snapshot) = graph.add_terminal(&key, title, handle, cwd);
        Ok(snapshot)
    }

    fn tabs_close(&self, params: &Value) -> Result<Value, String> {
        let Some(key) = self.worktree_key(params) else {
            return Err("invalid_argument".to_string());
        };
        let tab_id = params
            .get("tabId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let removed = {
            let mut graph = self.graph.lock().map_err(|_| "graph_unavailable")?;
            graph.close_tab(&key, tab_id)
        };
        let Some((handle, _snapshot)) = removed else {
            return Err("unknown_tab".to_string());
        };
        if let Ok(mut pty) = self.pty.lock() {
            let _ = pty.kill(&handle);
        }
        Ok(json!({ "closed": true }))
    }

    fn terminal_send(&self, params: &Value) -> Result<Value, String> {
        let handle = params
            .get("terminal")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let mut data = Vec::new();
        if params.get("interrupt").and_then(|v| v.as_bool()) == Some(true) {
            data.push(0x03);
        }
        if let Some(text) = params.get("text").and_then(|v| v.as_str()) {
            data.extend_from_slice(text.as_bytes());
        }
        if params.get("enter").and_then(|v| v.as_bool()) == Some(true) {
            data.push(b'\r');
        }
        let written = data.len();
        let mut pty = self.pty.lock().map_err(|_| "pty_unavailable")?;
        pty.write(handle, &data).map_err(|_| "unknown_terminal".to_string())?;
        Ok(json!({ "handle": handle, "accepted": true, "bytesWritten": written }))
    }

    fn terminal_read(&self, params: &Value) -> Result<Value, String> {
        let handle = params
            .get("terminal")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let cursor = params.get("cursor").and_then(|v| v.as_u64()).unwrap_or(0);
        let pty = self.pty.lock().map_err(|_| "pty_unavailable")?;
        let (start, bytes, seq) = pty
            .read(handle, cursor)
            .map_err(|_| "unknown_terminal".to_string())?;
        let mut text = String::from_utf8_lossy(&bytes).to_string();
        if let Some(limit) = params.get("limit").and_then(|v| v.as_u64()) {
            if text.len() > limit as usize {
                text = text.chars().take(limit as usize).collect();
            }
        }
        Ok(json!({
            "terminal": {
                "handle": handle,
                "text": text,
                "cursor": seq,
                "source": "stream",
                "truncated": start > cursor,
            }
        }))
    }

    fn terminal_list(&self, params: &Value) -> Value {
        let worktree = params.get("worktree").and_then(|v| v.as_str());
        let Ok(pty) = self.pty.lock() else {
            return json!({ "terminals": [] });
        };
        let terminals: Vec<Value> = pty
            .list()
            .iter()
            .filter(|info| {
                worktree.is_none_or(|w| {
                    pty.meta(&info.id).and_then(|m| m.worktree.as_deref()) == Some(w)
                })
            })
            .map(|info| terminal_json(&info.id, &pty))
            .collect();
        json!({ "terminals": terminals })
    }

    fn terminal_close(&self, params: &Value) -> Result<Value, String> {
        let handle = params
            .get("terminal")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "invalid_argument".to_string())?;
        let mut pty = self.pty.lock().map_err(|_| "pty_unavailable")?;
        pty.kill(handle).map_err(|_| "unknown_terminal".to_string())?;
        Ok(json!({}))
    }

    /// A worktree selector is a repo id (`id:<uuid>` or the bare
    /// id) or a filesystem path; resolve it to the repo's path
    /// via the profile store's catalog.
    fn resolve_worktree_path(&self, worktree: Option<&str>) -> Option<String> {
        let selector = worktree?;
        if std::path::Path::new(selector).is_dir() {
            return Some(selector.to_string());
        }
        let id = selector.strip_prefix("id:").unwrap_or(selector);
        let repos = self.repo_list();
        repos
            .as_array()?
            .iter()
            .find(|repo| repo.get("id").and_then(|v| v.as_str()) == Some(id))
            .and_then(|repo| repo.get("path").and_then(|v| v.as_str()).map(str::to_string))
    }

    fn status(&self, params: &Value, ctx: &Ctx) -> Value {
        if params.get("probe").and_then(|v| v.as_bool()) == Some(true) {
            return json!({ "runtimeId": self.runtime_id });
        }
        let (live_tabs, live_leaves) = self
            .graph
            .lock()
            .map(|graph| graph.counts())
            .unwrap_or((0, 0));
        let mut status = json!({
            "runtimeId": self.runtime_id,
            "rendererGraphEpoch": 0,
            "graphStatus": "ready",
            "authoritativeWindowId": Value::Null,
            "liveTabCount": live_tabs,
            "liveLeafCount": live_leaves,
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

/// The Terminal object for one live session: the fields
/// daemon-rs can honestly fill without the session graph.
fn terminal_json(handle: &str, pty: &crate::pty::PtyManager) -> Value {
    let info = pty.list().into_iter().find(|info| info.id == handle);
    let meta = pty.meta(handle);
    json!({
        "handle": handle,
        "ptyId": handle,
        "title": meta.and_then(|m| m.title.clone()),
        "cwd": meta.and_then(|m| m.cwd.clone()),
        "worktreeId": meta.and_then(|m| m.worktree.clone()),
        "state": match info.as_ref().map(|i| i.state) {
            Some(crate::pty::SessionState::Running) => "running",
            _ => "exited",
        },
        "createdAt": meta.map(|m| m.created_at_ms).unwrap_or(0),
        "cols": info.as_ref().map(|i| i.cols).unwrap_or(0),
        "rows": info.as_ref().map(|i| i.rows).unwrap_or(0),
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
            Arc::new(Mutex::new(Registry::load(dir.clone()))),
            dir,
            Arc::new(Mutex::new(crate::pty::PtyManager::new())),
            Arc::new(Mutex::new(crate::graph::Graph::new())),
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
    fn repo_list_reads_the_profile_state_store() {
        let dir =
            std::env::temp_dir().join(format!("daemon-rs-repos-{}", std::process::id()));
        let store_dir = dir.join("profiles").join("local-default");
        std::fs::create_dir_all(&store_dir).unwrap();
        let db_path = store_dir.join("profile-state.db");
        let _ = std::fs::remove_file(&db_path);
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE profile_state_documents (
                domain TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL,
                domain_version INTEGER NOT NULL, revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL, content_hash TEXT NOT NULL
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO profile_state_documents VALUES ('repos', ?1, 1, 1, 0, 'x')",
            [r#"[{"id":"r1","path":"/tmp/a","displayName":"a","kind":"git"}]"#],
        )
        .unwrap();
        drop(conn);
        let mut rpc = Rpc::new(
            "runtime-test".to_string(),
            Arc::new(Mutex::new(Registry::load(dir.clone()))),
            dir,
            Arc::new(Mutex::new(crate::pty::PtyManager::new())),
            Arc::new(Mutex::new(crate::graph::Graph::new())),
        );
        let response = rpc
            .handle(r#"{"id":"7","method":"repo.list","params":{}}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["result"]["repos"][0]["id"], "r1");
        assert_eq!(parsed["result"]["repos"][0]["displayName"], "a");
    }

    #[test]
    fn terminal_round_trip() {
        let mut rpc = rpc();
        let response = rpc
            .handle(r#"{"id":"t1","method":"terminal.create","params":{}}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        let handle = parsed["result"]["terminal"]["handle"].as_str().unwrap().to_string();
        assert_eq!(parsed["result"]["terminal"]["state"], "running");
        let send = json!({
            "id": "t2",
            "method": "terminal.send",
            "params": { "terminal": handle, "text": "echo rpc-marker", "enter": true },
        });
        let response = rpc.handle(&send.to_string(), &anon()).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["accepted"], true);
        // Poll the stream read until the shell echoes the marker.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut text = String::new();
        while std::time::Instant::now() < deadline {
            let read = json!({
                "id": "t3",
                "method": "terminal.read",
                "params": { "terminal": handle },
            });
            let response = rpc.handle(&read.to_string(), &anon()).unwrap();
            let parsed: Value = serde_json::from_str(&response).unwrap();
            text = parsed["result"]["terminal"]["text"].as_str().unwrap().to_string();
            if text.contains("rpc-marker") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(text.contains("rpc-marker"), "read was: {text}");
        let response = rpc
            .handle(r#"{"id":"t4","method":"terminal.list","params":{}}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["terminals"].as_array().unwrap().len(), 1);
        let close = json!({
            "id": "t5",
            "method": "terminal.close",
            "params": { "terminal": handle },
        });
        let response = rpc.handle(&close.to_string(), &anon()).unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], true);
        let response = rpc
            .handle(r#"{"id":"t6","method":"terminal.list","params":{}}"#, &anon())
            .unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"]["terminals"].as_array().unwrap().len(), 0);
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
