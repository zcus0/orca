// orca-serve-rs — Fase 1 milestone 2.
//
// Architecture (from the upstream audit): upstream ships a headless server,
// `orcad` ("the Orca runtime served without Electron"), which natively
//   * serves the bundled web client (--web-client-root),
//   * opens the runtime WebSocket listener, and
//   * terminates the E2EE pairing handshake itself (framing v2 / legacy).
// So this Rust binary does NOT reimplement any protocol or crypto. It is a
// supervisor + transparent front:
//   * spawns orcad with --port 0 --json, reads its `orca_server_ready` line,
//   * proxies HTTP and WebSocket byte-faithfully to orcad's loopback port
//     (WS message payloads are forwarded untouched, so the pairing handshake
//     stays bit-compatible by construction),
//   * exposes /healthz with the child state, and prints orcad's pairing URL
//     to stdout once ready (the operator channel, same as upstream serve).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ws::{Message as AxMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

#[derive(Default, Clone)]
struct OrcadInfo {
    ready: bool,
    pid: Option<u32>,
    port: Option<u16>,
    runtime_id: Option<String>,
}

struct AppState {
    info: RwLock<OrcadInfo>,
    http: reqwest::Client,
}

struct Args {
    bind: String,
    port: u16,
    orcad_entry: PathBuf,
    node: String,
    web_dir: PathBuf,
    data_dir: PathBuf,
    pairing_address: Option<String>,
    allow_public: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        bind: "127.0.0.1".into(),
        port: 6770,
        orcad_entry: PathBuf::from("../fork/out/orcad/orcad.js"),
        node: "node".into(),
        web_dir: PathBuf::from("../fork/out/web"),
        data_dir: PathBuf::from("/tmp/orca-serve-rs/data"),
        pairing_address: None,
        allow_public: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let mut take = |i: &mut usize| -> String {
            *i += 1;
            argv.get(*i).cloned().unwrap_or_default()
        };
        match argv[i].as_str() {
            "--bind" => a.bind = take(&mut i),
            "--port" => a.port = take(&mut i).parse().unwrap_or(6770),
            "--orcad-entry" => a.orcad_entry = PathBuf::from(take(&mut i)),
            "--node" => a.node = take(&mut i),
            "--web-dir" => a.web_dir = PathBuf::from(take(&mut i)),
            "--data-dir" => a.data_dir = PathBuf::from(take(&mut i)),
            "--pairing-address" => a.pairing_address = Some(take(&mut i)),
            "--allow-public" => a.allow_public = true,
            other => eprintln!("ignoring unknown arg: {other}"),
        }
        i += 1;
    }
    a
}

async fn spawn_orcad(args: &Args, state: Arc<AppState>) -> std::io::Result<Child> {
    tokio::fs::create_dir_all(&args.data_dir).await?;
    let mut cmd = Command::new(&args.node);
    cmd.arg(&args.orcad_entry)
        .arg("--port")
        .arg("0")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--web-client-root")
        .arg(&args.web_dir)
        .arg("--json")
        .env("ORCA_USER_DATA", &args.data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if let Some(addr) = &args.pairing_address {
        cmd.arg("--pairing-address").arg(addr);
    }
    if args.allow_public {
        cmd.arg("--allow-public");
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    state.info.write().await.pid = pid;

    let stdout = child.stdout.take().expect("stdout piped");
    let st = state.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    if v.get("type").and_then(|t| t.as_str()) == Some("orca_server_ready") {
                        let port = v
                            .get("boundEndpoint")
                            .and_then(|e| e.as_str())
                            .and_then(|e| e.rsplit(':').next())
                            .and_then(|p| p.parse::<u16>().ok());
                        let mut info = st.info.write().await;
                        info.ready = true;
                        info.port = port;
                        info.runtime_id = v
                            .get("runtimeId")
                            .and_then(|r| r.as_str())
                            .map(|s| s.to_string());
                        drop(info);
                        println!("orcad ready: endpoint port {:?}", port);
                        if let Some(url) = v
                            .get("pairing")
                            .and_then(|p| p.get("url"))
                            .and_then(|u| u.as_str())
                        {
                            println!("Pairing URL: {url}");
                        }
                        continue;
                    }
                }
            }
            println!("orcad: {line}");
        }
    });
    Ok(child)
}

async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let info = state.info.read().await;
    let body = format!(
        "{{\"ok\":true,\"orcad_ready\":{},\"orcad_pid\":{},\"orcad_port\":{}}}",
        info.ready,
        info.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".into()),
        info.port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "null".into()),
    );
    ([(axum::http::header::CONTENT_TYPE, "application/json")], body)
}

fn is_ws_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

async fn proxy(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let port = {
        let info = state.info.read().await;
        info.port
    };
    let Some(port) = port else {
        return (StatusCode::SERVICE_UNAVAILABLE, "orcad not ready").into_response();
    };
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    if is_ws_upgrade(req.headers()) {
        let (mut parts, _body) = req.into_parts();
        let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
            Ok(ws) => ws,
            Err(e) => return e.into_response(),
        };
        let upstream = format!("ws://127.0.0.1:{port}{path_and_query}");
        return ws
            .on_upgrade(move |socket| bridge_ws(socket, upstream))
            .into_response();
    }

    // Plain HTTP proxy.
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "body too large").into_response(),
    };
    let url = format!("http://127.0.0.1:{port}{path_and_query}");
    let mut rb = state.http.request(method, &url).body(body_bytes);
    for (k, v) in headers.iter() {
        if k == axum::http::header::HOST || k == axum::http::header::CONNECTION {
            continue;
        }
        rb = rb.header(k, v);
    }
    match rb.send().await {
        Ok(resp) => {
            let status = resp.status();
            let mut builder = Response::builder().status(status);
            for (k, v) in resp.headers().iter() {
                if k == axum::http::header::CONNECTION {
                    continue;
                }
                builder = builder.header(k, v);
            }
            let stream = resp.bytes_stream();
            builder
                .body(Body::from_stream(stream))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => {
            eprintln!("proxy http error: {e}");
            (StatusCode::BAD_GATEWAY, "upstream error").into_response()
        }
    }
}

/// Forward WS messages both ways, payloads untouched.
async fn bridge_ws(downstream: WebSocket, upstream_url: String) {
    let upstream = match tokio_tungstenite::connect_async(&upstream_url).await {
        Ok((s, _)) => s,
        Err(e) => {
            eprintln!("bridge: upstream connect failed: {e}");
            return;
        }
    };
    let (mut up_tx, mut up_rx) = upstream.split();
    let (mut dn_tx, mut dn_rx) = downstream.split();

    let to_up = tokio::spawn(async move {
        while let Some(Ok(msg)) = dn_rx.next().await {
            let out = match msg {
                AxMessage::Binary(b) => {
                    tokio_tungstenite::tungstenite::Message::Binary(b.to_vec().into())
                }
                AxMessage::Text(t) => {
                    tokio_tungstenite::tungstenite::Message::Text(t.to_string().into())
                }
                AxMessage::Ping(p) => {
                    tokio_tungstenite::tungstenite::Message::Ping(p.to_vec().into())
                }
                AxMessage::Pong(p) => {
                    tokio_tungstenite::tungstenite::Message::Pong(p.to_vec().into())
                }
                AxMessage::Close(_) => break,
            };
            if up_tx.send(out).await.is_err() {
                break;
            }
        }
        let _ = up_tx
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
    });

    let to_dn = tokio::spawn(async move {
        while let Some(Ok(msg)) = up_rx.next().await {
            use tokio_tungstenite::tungstenite::Message as TMessage;
            let out = match msg {
                TMessage::Binary(b) => AxMessage::Binary(b.to_vec().into()),
                TMessage::Text(t) => AxMessage::Text(t.to_string().into()),
                TMessage::Ping(p) => AxMessage::Ping(p.to_vec().into()),
                TMessage::Pong(p) => AxMessage::Pong(p.to_vec().into()),
                TMessage::Close(_) => break,
                TMessage::Frame(_) => continue,
            };
            if dn_tx.send(out).await.is_err() {
                break;
            }
        }
        let _ = dn_tx.send(AxMessage::Close(None)).await;
    });

    let _ = tokio::join!(to_up, to_dn);
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let state = Arc::new(AppState {
        info: RwLock::new(OrcadInfo::default()),
        http: reqwest::Client::new(),
    });

    let mut orcad_child = match spawn_orcad(&args, state.clone()).await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("failed to spawn orcad: {e}");
            None
        }
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .expect("bind address");
    println!(
        "orca-serve-rs listening on http://{addr} (fronting orcad serve mode)"
    );
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");

    if let Some(mut child) = orcad_child.take() {
        let _ = child.kill().await;
    }
}
