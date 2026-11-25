//! orca-daemon-rs — Fase 3: the Orca daemon rewritten in Rust.
//!
//! Serves the web client plus the E2EE v2 WebSocket channel from
//! the separate Orca RS profile (`orca-rs` beside the original's
//! `orca`, imported as a copy on first run). M1: identity/status.
//! M2: pairing — the v2 handshake, sealed frames, and device auth
//! (token + device-key), bit-compatible with upstream. M3: the RPC
//! surface (status, pairing writes, workspace reads). M4/M5:
//! terminals and agent sessions.
//!
//! Two hosts run this crate: the standalone `orca-daemon-rs`
//! binary (headless server) and the Rust desktop app (app-rs),
//! which links it in-process — one binary, one runtime, no Node.

mod channel;
mod e2ee;
mod graph;
mod multiplex;
mod profile_state;
mod pty;
mod registry;
mod rpc;
mod stream;

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
pub fn resolve_profile_dir() -> PathBuf {
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
    web_root: Option<PathBuf>,
    pty: Arc<std::sync::Mutex<pty::PtyManager>>,
    graph: Arc<std::sync::Mutex<graph::Graph>>,
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
async fn static_file(uri: axum::http::Uri, State(state): State<AppState>) -> impl IntoResponse {
    let root = state
        .web_root
        .as_ref()
        .map(|dir| dir.display().to_string())
        .or_else(|| std::env::var("ORCA_RS_WEB_ROOT").ok())
        .unwrap_or_else(|| "out/web".to_string());
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

/// The push side of one client connection: background producers
/// (terminal output pumps, M4 slice 3b) seal binary stream frames
/// through the shared channel and hand the wire bytes to the
/// writer task's queue. The handshake/RPC loop uses the same path,
/// so every outbound frame funnels through one writer.
#[derive(Clone)]
pub(crate) struct Outbound {
    channel: Arc<std::sync::Mutex<Channel>>,
    queue: tokio::sync::mpsc::Sender<Message>,
}

impl Outbound {
    /// Seals one binary payload (a terminal stream frame) and
    /// queues it for the writer. False = the connection is gone.
    pub(crate) async fn send_binary(&self, plaintext: &[u8]) -> bool {
        let sealed = self
            .channel
            .lock()
            .ok()
            .and_then(|mut channel| channel.seal_binary(plaintext));
        match sealed {
            Some(bytes) => self.queue.send(Message::Binary(bytes.into())).await.is_ok(),
            None => false,
        }
    }

    /// Queues an already-framed text message (handshake replies
    /// and sealed auth frames travel unsealed-or-presealed).
    pub(crate) async fn send_text(&self, text: String) -> bool {
        self.queue.send(Message::Text(text.into())).await.is_ok()
    }
}

async fn handle_ws(socket: WebSocket, state: AppState) {
    let profile = state.profile.clone();
    let (mut sink, mut stream) = socket.split();
    let (queue_tx, mut queue_rx) = tokio::sync::mpsc::channel::<Message>(256);
    let writer = tokio::spawn(async move {
        while let Some(message) = queue_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let Some(server_secret) = profile.server_secret else {
        println!("[daemon-rs] ws rejected: profile has no usable E2EE keypair");
        let _ = queue_tx
            .send(Message::Close(Some(CloseFrame {
                code: 4001,
                reason: "Host key unavailable".into(),
            })))
            .await;
        drop(queue_tx);
        let _ = writer.await;
        return;
    };
    let devices = state
        .registry
        .lock()
        .map(|registry| registry.devices())
        .unwrap_or_default();
    let channel = Arc::new(std::sync::Mutex::new(Channel::new(server_secret, devices)));
    let outbound = Outbound { channel: channel.clone(), queue: queue_tx.clone() };
    let mut rpc = rpc::Rpc::new(
        profile.runtime_id_current.clone(),
        state.registry.clone(),
        profile.dir.clone(),
        state.pty.clone(),
        state.graph.clone(),
    );
    let mut mux = multiplex::Multiplex::new(state.pty.clone(), outbound.clone());
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    println!("[daemon-rs] client websocket connected");
    loop {
        let ready = channel.lock().map(|c| c.is_ready()).unwrap_or(false);
        let next = if ready {
            stream.next().await
        } else {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(next) => next,
                Err(_) => {
                    let _ = outbound
                        .queue
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
        let actions = {
            let Ok(mut channel) = channel.lock() else { break };
            match msg {
                Message::Text(text) => channel.on_text(&text),
                Message::Binary(bytes) => channel.on_binary(&bytes),
                Message::Close(_) => break,
                _ => continue,
            }
        };
        let mut close = false;
        for action in actions {
            match action {
                Action::SendText(text) => {
                    if !outbound.send_text(text).await {
                        close = true;
                        break;
                    }
                }
                Action::Close(code, reason) => {
                    let _ = outbound
                        .queue
                        .send(Message::Close(Some(CloseFrame { code, reason: reason.into() })))
                        .await;
                    close = true;
                    break;
                }
                Action::Authenticated(device_id) => {
                    println!("[daemon-rs] device authenticated: {device_id}");
                    let device_token = channel.lock().ok().and_then(|c| c.device_token().map(str::to_string));
                    if let Ok(mut registry) = state.registry.lock() {
                        registry.note_auth(&device_id, device_token.as_deref());
                    }
                }
                Action::RpcText(text) => {
                    let method = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_string))
                        .unwrap_or_else(|| "?".to_string());
                    println!("[daemon-rs] rpc: {method}");
                    let (device_id, device_token, transcript_hash_b64) = channel
                        .lock()
                        .map(|c| {
                            (
                                c.device_id().map(str::to_string),
                                c.device_token().map(str::to_string),
                                c.transcript_hash_b64(),
                            )
                        })
                        .unwrap_or((None, None, None));
                    let ctx = rpc::Ctx { device_id, device_token, transcript_hash_b64 };
                    if let Some(response) = rpc.handle(&text, &ctx) {
                        let sealed = channel.lock().ok().and_then(|mut c| c.seal_text(&response));
                        match sealed {
                            Some(sealed) => {
                                if !outbound.send_text(sealed).await {
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
                    mux.on_binary(&bytes).await;
                }
            }
        }
        if close {
            break;
        }
    }
    mux.shutdown();
    drop(outbound);
    drop(queue_tx);
    let _ = writer.await;
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

/// How the daemon is launched: the standalone binary fills this
/// from env vars; the Rust desktop app fills it from its bundle.
pub struct DaemonConfig {
    /// None = resolve_profile_dir() (the separate `orca-rs` profile).
    pub profile_dir: Option<PathBuf>,
    /// 0 = an ephemeral port chosen by the OS (the desktop app).
    pub port: u16,
    /// Web client build to serve. None = ORCA_RS_WEB_ROOT / out/web.
    pub web_root: Option<PathBuf>,
}

/// A running daemon: where its client is, and its serve task.
pub struct RunningDaemon {
    pub port: u16,
    /// The full URL carrying the pairing offer — the desktop
    /// window opens this so it pairs with its own in-process
    /// daemon on first run.
    pub pairing_url: Option<String>,
    pub web_url: String,
    pub handle: tokio::task::JoinHandle<()>,
}

/// Starts the daemon and returns once it is listening. The serve
/// loop runs in a spawned task; dropping the handle does not stop
/// it (the desktop app parks its daemon thread instead).
pub async fn start(config: DaemonConfig) -> std::io::Result<RunningDaemon> {
    let dir = config.profile_dir.unwrap_or_else(resolve_profile_dir);
    std::fs::create_dir_all(&dir)?;
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
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.port)).await?;
    let port = listener.local_addr()?.port();
    let mut pairing_url = None;
    if let Some(public_key) = profile.public_key_b64.clone() {
        pairing_url = registry
            .lock()
            .ok()
            .and_then(|mut registry| registry.mint_offer(&public_key, port));
        if let Some(url) = &pairing_url {
            println!("[daemon-rs] pairing: {url}");
        }
    }
    let state = AppState {
        profile: Arc::new(profile),
        registry,
        web_root: config.web_root,
        pty: Arc::new(std::sync::Mutex::new(pty::PtyManager::new())),
        graph: Arc::new(std::sync::Mutex::new(graph::Graph::new())),
    };
    let app = Router::new()
        .route("/__daemon_rs_status", get(status))
        .route("/ws", get(ws_handler))
        .fallback(get(static_file))
        .with_state(state);
    println!("[daemon-rs] listening on http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(RunningDaemon {
        port,
        web_url: format!("http://127.0.0.1:{port}/web-index.html"),
        pairing_url,
        handle,
    })
}
