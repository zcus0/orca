#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{Manager, RunEvent};

struct RuntimeState(Mutex<Option<Child>>);

fn node_file_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "node.exe"
    } else {
        "node"
    }
}

/// Spawns the bundled orcad in serve mode on an ephemeral loopback port and
/// returns the child plus the web client URL from its readiness line. The URL
/// carries the pairing offer, so the window pairs with the local runtime.
fn spawn_orcad(
    node: &Path,
    orcad_entry: &Path,
    web_dir: &Path,
    data_dir: &Path,
) -> Result<(Child, String), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("data dir: {e}"))?;
    let mut child = Command::new(node)
        .arg(orcad_entry)
        .args(["--port", "0", "--bind", "127.0.0.1", "--json"])
        .arg("--web-client-root")
        .arg(web_dir)
        .env("ORCA_USER_DATA", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to start the bundled runtime: {e}"))?;
    let stdout = child.stdout.take().ok_or("orcad stdout unavailable")?;
    let mut reader = BufReader::new(stdout);
    let mut web_url: Option<String> = None;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if value.get("type").and_then(|t| t.as_str()) == Some("orca_server_ready") {
            web_url = value
                .get("pairing")
                .and_then(|p| p.get("webClientUrl"))
                .and_then(|u| u.as_str())
                .map(str::to_string)
                .or_else(|| {
                    value
                        .get("boundEndpoint")
                        .and_then(|b| b.as_str())
                        .map(|b| {
                            format!(
                                "http://{}/web-index.html",
                                b.trim_start_matches("ws://")
                            )
                        })
                });
            break;
        }
    }
    // Keep draining stdout so orcad can never block on a full pipe.
    std::thread::spawn(move || {
        let mut sink = String::new();
        loop {
            sink.clear();
            match reader.read_line(&mut sink) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let url = web_url.ok_or("orcad exited without reporting a web client URL")?;
    Ok((child, url))
}

fn start_local_runtime(app: &tauri::AppHandle) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let resource_dir = match handle.path().resource_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("orca-rs: resource dir unavailable: {e}");
                return;
            }
        };
        let data_dir = match handle.path().app_data_dir() {
            Ok(dir) => dir.join("runtime"),
            Err(e) => {
                eprintln!("orca-rs: app data dir unavailable: {e}");
                return;
            }
        };
        let node = resource_dir.join(node_file_name());
        let entry = resource_dir.join("orcad").join("orcad.js");
        let web = resource_dir.join("web");
        match spawn_orcad(&node, &entry, &web, &data_dir) {
            Ok((child, url)) => {
                if let Some(state) = handle.try_state::<RuntimeState>() {
                    if let Ok(mut slot) = state.0.lock() {
                        *slot = Some(child);
                    }
                }
                if let Some(window) = handle.get_webview_window("main") {
                    if let Ok(parsed) = url.parse::<tauri::Url>() {
                        let _ = window.navigate(parsed);
                    }
                }
            }
            Err(e) => eprintln!("orca-rs: local runtime failed to start: {e}"),
        }
    });
}

/// Headless smoke test: ORCA_RS_TEST_SPAWN=1 with ORCA_RS_NODE,
/// ORCA_RS_ORCAD_ENTRY, ORCA_RS_WEB_DIR and ORCA_RS_DATA_DIR set prints the
/// web client URL the window would open, then kills the runtime.
fn headless_test_requested() -> bool {
    std::env::var("ORCA_RS_TEST_SPAWN").is_ok()
}

fn run_headless_test() {
    let env = |key: &str| -> PathBuf {
        PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("missing env {key}")))
    };
    match spawn_orcad(
        &env("ORCA_RS_NODE"),
        &env("ORCA_RS_ORCAD_ENTRY"),
        &env("ORCA_RS_WEB_DIR"),
        &env("ORCA_RS_DATA_DIR"),
    ) {
        Ok((mut child, url)) => {
            println!("WEB_CLIENT_URL {url}");
            let _ = child.kill();
        }
        Err(e) => {
            eprintln!("SPAWN_FAILED {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    if headless_test_requested() {
        run_headless_test();
        return;
    }
    let app = tauri::Builder::default()
        .manage(RuntimeState(Mutex::new(None)))
        .setup(|app| {
            start_local_runtime(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Orca RS");
    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<RuntimeState>() {
                if let Ok(mut slot) = state.0.lock() {
                    if let Some(mut child) = slot.take() {
                        let _ = child.kill();
                    }
                }
            }
        }
    });
}
