//! orca-daemon-rs — Fase 3.
//!
//! Reads the ORIGINAL Orca profile directory (the same one Orca RS
//! 0.2.2 points orcad at) and serves the web client plus the E2EE
//! v2 WebSocket channel. M1: identity/status. M2: pairing — the v2
//! handshake, sealed frames, and device auth (token + device-key),
//! bit-compatible with upstream. RPC payloads past auth are logged
//! until M3 implements them.

mod channel;
mod e2ee;
mod registry;
mod rpc;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};

use channel::{Action, Channel};

struct Profile {
    dir: PathBuf,
    installation_id: Option<String>,
    public_key_b64: Option<String>,
    runtime_id: Option<String>,
    /// The host E2EE secret (in memory only, never logged or sent).
    server_secret: Option<[u8; 32]>,
    /// This process run's runtime id (RPC _meta.runtimeId).
    runtime_id_current: String,
}

fn config_root() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config")
}

/// Orca RS is its own runtime, separate from normal Orca, so both
/// can run at once: its profile lives in `orca-rs` beside the
/// original's `orca`. On first run (no `orca-rs` yet) the original
/// profile is imported as a copy — identity, devices, settings —
/// minus live runtime state (daemon socket dir, instance lock,
/// stale runtime record). After that the two evolve independently.
/// ORCA_RS_PROFILE overrides the location (and skips the import).
fn resolve_profile_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("ORCA_RS_PROFILE") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    let root = config_root();
    let rs_dir = root.join("orca-rs");
    if rs_dir.exists() {
        return rs_dir;
    }
    let legacy = root.join("orca");
    if legacy.is_dir() {
        match import_profile(&legacy, &rs_dir) {
            Ok(()) => println!("[daemon-rs] imported original Orca profile into {}", rs_dir.display()),
            Err(error) => println!("[daemon-rs] profile import failed: {error}"),
        }
    }
    rs_dir
}

fn import_profile(from: &PathBuf, to: &PathBuf) -> std::io::Result<()> {
    const EXCLUDED: [&str; 3] = ["daemon", "orcad.lock", "orca-runtime.json"];
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        if EXCLUDED.contains(&entry.file_name().to_string_lossy().as_ref()) {
            continue;
        }
        copy_recursive(&entry.path(), &to.join(entry.file_name()))?;
    }
    Ok(())
}

fn copy_recursive(from: &PathBuf, to: &PathBuf) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

fn read_json(dir: &PathBuf, name: &str) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(dir.join(name)).ok()?;
    serde_json::from_str(&text).ok()
}

fn load_profile(dir: PathBuf) -> Profile {
    let installation_id = read_json(&dir, "host-installation.json")
        .and_then(|v| v.get("installationId").and_then(|s| s.as_str()).map(str::to_string));
    let keypair = read_json(&dir, "orca-e2ee-keypair.json");
    let public_key_b64 = keypair
        .as_ref()
        .and_then(|v| v.get("publicKeyB64").and_then(|s| s.as_str()).map(str::to_string));
    let server_secret = keypair
        .as_ref()
        .and_then(|v| v.get("secretKeyB64").and_then(|s| s.as_str()))
        .and_then(|s| e2ee::b64_decode_canonical(s, 32))
        .and_then(|bytes| bytes.first_chunk::<32>().copied());
    let runtime_id = read_json(&dir, "orca-runtime.json")
        .and_then(|v| v.get("runtimeId").and_then(|s| s.as_str()).map(str::to_string));
    Profile {
        dir,
        installation_id,
        public_key_b64,
        runtime_id,
        server_secret,
        runtime_id_current: mint_runtime_id(),
    }
}

#[derive(Clone)]
struct AppState {
    profile: Arc<Profile>,
    registry: Arc<std::sync::Mutex<registry::Registry>>,
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let profile = &state.profile;
    let paired = state.registry.lock().map(|r| r.count()).unwrap_or(0);
    axum::Json(serde_json::json!({
        "daemon": "orca-daemon-rs",
        "milestone": "M3",
        "profileDir": profile.dir.display().to_string(),
        "installationId": profile.installation_id,
        "hostPublicKeyB64": profile.public_key_b64,
        "pairedDevices": paired,
        "lastRuntimeId": profile.runtime_id,
        "runtimeId": profile.runtime_id_current,
    }))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

/// A per-run runtime id (the _meta.runtimeId of every RPC reply).
fn mint_runtime_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "daemon-rs".to_string();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal static file serving for the web client build (M1: enough
/// for the client to load; orcad's own serving has more headers and
/// caching rules). Root from ORCA_RS_WEB_ROOT, defaulting to the
/// fork's out/web.
async fn static_file(uri: axum::http::Uri) -> impl IntoResponse {
    let root = std::env::var("ORCA_RS_WEB_ROOT")
        .unwrap_or_else(|_| "out/web".to_string());
    let rel = uri.path().trim_start_matches('/');
    let rel = if rel.is_empty() { "web-index.html" } else { rel };
    if rel.contains("..") {
        return axum::http::StatusCode::BAD_REQUEST.into_response();
    }
    let path = PathBuf::from(&root).join(rel);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let content_type = match path.extension().and_then(|e| e.to_str()) {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "text/javascript",
                Some("css") => "text/css",
                Some("json") => "application/json",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("woff2") => "font/woff2",
                _ => "application/octet-stream",
            };
            ([(axum::http::header::CONTENT_TYPE, content_type)], bytes).into_response()
        }
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

/// Upstream's paired handshake deadline (paired-e2ee-handshake-deadline).
const HANDSHAKE_DEADLINE: Duration = Duration::from_millis(10_000);

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    let profile = state.profile.clone();
    let Some(server_secret) = profile.server_secret else {
        println!("[daemon-rs] ws rejected: profile has no usable E2EE keypair");
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: 4001,
                reason: "Host key unavailable".into(),
            })))
            .await;
        return;
    };
    let devices = state
        .registry
        .lock()
        .map(|registry| registry.devices())
        .unwrap_or_default();
    let mut channel = Channel::new(server_secret, devices);
    let mut rpc = rpc::Rpc::new(profile.runtime_id_current.clone(), state.registry.clone());
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    println!("[daemon-rs] client websocket connected");
    loop {
        let next = if channel.is_ready() {
            socket.next().await
        } else {
            match tokio::time::timeout_at(deadline, socket.next()).await {
                Ok(next) => next,
                Err(_) => {
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: 4002,
                            reason: "E2EE handshake timeout".into(),
                        })))
                        .await;
                    break;
                }
            }
        };
        let Some(Ok(msg)) = next else { break };
        let actions = match msg {
            Message::Text(text) => channel.on_text(&text),
            Message::Binary(bytes) => channel.on_binary(&bytes),
            Message::Close(_) => break,
            _ => continue,
        };
        let mut close = false;
        for action in actions {
            match action {
                Action::SendText(text) => {
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        close = true;
                        break;
                    }
                }
                Action::Close(code, reason) => {
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame { code, reason: reason.into() })))
                        .await;
                    close = true;
                    break;
                }
                Action::Authenticated(device_id) => {
                    println!("[daemon-rs] device authenticated: {device_id}");
                    if let Ok(mut registry) = state.registry.lock() {
                        registry.note_auth(&device_id, channel.device_token());
                    }
                }
                Action::RpcText(text) => {
                    let method = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string))
                        .unwrap_or_else(|| "?".to_string());
                    println!("[daemon-rs] rpc: {method}");
                    let ctx = rpc::Ctx {
                        device_id: channel.device_id().map(str::to_string),
                        device_token: channel.device_token().map(str::to_string),
                        transcript_hash_b64: channel.transcript_hash_b64(),
                    };
                    if let Some(response) = rpc.handle(&text, &ctx) {
                        match channel.seal_text(&response) {
                            Some(sealed) => {
                                if socket.send(Message::Text(sealed.into())).await.is_err() {
                                    close = true;
                                    break;
                                }
                            }
                            None => {
                                close = true;
                                break;
                            }
                        }
                    }
                }
                Action::RpcBinary(bytes) => {
                    println!("[daemon-rs] rpc binary (M4): {} bytes", bytes.len());
                }
            }
        }
        if close {
            break;
        }
    }
    println!("[daemon-rs] client websocket closed");
}

/// First run on a fresh RS profile: mint the host identity the
/// way upstream does — an installation id and the E2EE host
/// keypair — so the daemon is pairable out of the box. Existing
/// files are never touched.
fn ensure_identity(dir: &PathBuf) {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    if !dir.join("orca-e2ee-keypair.json").exists() {
        let mut secret = [0u8; 32];
        if getrandom::fill(&mut secret).is_ok() {
            let public = e2ee::public_key_from_secret(&secret);
            let keypair = serde_json::json!({
                "v": 1,
                "publicKeyB64": engine.encode(public),
                "secretKeyB64": engine.encode(secret),
            });
            write_secret_file(&dir.join("orca-e2ee-keypair.json"), &keypair.to_string());
            println!("[daemon-rs] generated host E2EE keypair (first run)");
        }
    }
    if !dir.join("host-installation.json").exists() {
        let installation = serde_json::json!({ "installationId": registry::uuid() });
        write_secret_file(&dir.join("host-installation.json"), &installation.to_string());
        println!("[daemon-rs] generated installation id (first run)");
    }
}

fn write_secret_file(path: &PathBuf, contents: &str) {
    if std::fs::write(path, contents).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[tokio::main]
async fn main() {
    let dir = resolve_profile_dir();
    let _ = std::fs::create_dir_all(&dir);
    ensure_identity(&dir);
    let profile = load_profile(dir);
    println!("[daemon-rs] profile: {}", profile.dir.display());
    println!("[daemon-rs] installationId: {:?}", profile.installation_id);
    let registry = registry::Registry::load(profile.dir.clone());
    let registry = Arc::new(std::sync::Mutex::new(registry));
    println!(
        "[daemon-rs] paired devices: {}",
        registry.lock().map(|r| r.count()).unwrap_or(0)
    );
    let port: u16 = std::env::var("ORCA_DAEMON_RS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6773);
    if let Some(public_key) = profile.public_key_b64.clone() {
        let url = registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.mint_offer(&public_key, port));
        if let Some(url) = url {
            println!("[daemon-rs] pairing: {url}");
        }
    }
    let state = AppState { profile: Arc::new(profile), registry };
    let app = Router::new()
        .route("/__daemon_rs_status", get(status))
        .route("/ws", get(ws_handler))
        .fallback(get(static_file))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind");
    println!("[daemon-rs] listening on http://127.0.0.1:{port}");
    axum::serve(listener, app).await.expect("serve");
}
