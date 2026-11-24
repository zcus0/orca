#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{Manager, RunEvent};

struct RuntimeState(Mutex<Option<Child>>);

/// Resolves the Node runtime the bundled orcad slot is pinned to, mirroring
/// upstream's orcad-bundled-runtime: the slot's `.server-target` and
/// `.runtime-node` marker name a runtime at
/// `<resources>/runtimes/node-<sha256>/` (`node.exe` for win32 targets,
/// `bin/node` otherwise). Spawning that exact runtime also skips orcad's
/// launcher handoff, so the child we hold is the real server process.
fn resolve_pinned_node(resource_dir: &Path, orcad_dir: &Path) -> Result<PathBuf, String> {
    let target = std::fs::read_to_string(orcad_dir.join(".server-target"))
        .map_err(|e| format!("cannot read the bundled runtime target: {e}"))?;
    let sha = std::fs::read_to_string(orcad_dir.join(".runtime-node"))
        .map_err(|e| format!("cannot read the bundled runtime marker: {e}"))?;
    let exe: PathBuf = if target.trim().starts_with("win32") {
        PathBuf::from("node.exe")
    } else {
        PathBuf::from("bin").join("node")
    };
    let runtime = resource_dir
        .join("runtimes")
        .join(format!("node-{}", sha.trim()))
        .join(exe);
    if !runtime.exists() {
        return Err(format!(
            "the bundled Node runtime is missing at {}",
            runtime.display()
        ));
    }
    Ok(runtime)
}

/// Spawns the bundled orcad in serve mode on an ephemeral loopback port and
/// returns the child plus the web client URL from its readiness line. The URL
/// carries the pairing offer, so the window pairs with the local runtime.
/// orcad's stderr goes to a log file in the data dir: a GUI process has no
/// console to inherit, and the log is the evidence when startup fails.
fn spawn_orcad(
    node: &Path,
    orcad_entry: &Path,
    web_dir: &Path,
    data_dir: &Path,
) -> Result<(Child, String), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("data dir: {e}"))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("runtime.log"))
        .map_err(|e| format!("runtime log: {e}"))?;
    let mut child = Command::new(node)
        .arg(orcad_entry)
        .args(["--port", "0", "--bind", "127.0.0.1", "--json"])
        .arg("--web-client-root")
        .arg(web_dir)
        .env("ORCA_USER_DATA", data_dir)
        .env("ORCA_USER_DATA_PATH", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log))
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
    let url = web_url.ok_or(
        "orcad exited without reporting a web client URL (see runtime.log in the app data dir)",
    )?;
    Ok((child, url))
}

/// Shows a startup failure on the loading page instead of hanging silently.
fn show_startup_error(app: &tauri::AppHandle, message: &str) {
    eprintln!("orca-rs: {message}");
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(js_arg) = serde_json::to_string(&format!("Orca runtime failed to start: {message}")) {
            let _ = window.eval(format!(
                "document.getElementById('status').textContent = {js_arg}"
            ));
        }
    }
}

/// The original Orca profile directory, mirroring upstream's
/// getPlatformUserDataPath (the packaged app's own profile): %APPDATA%\orca
/// on Windows, ~/Library/Application Support/orca on macOS, ~/.config/orca
/// on Linux. The local runtime must use this profile — not a fresh one — so
/// it keeps the user's installation identity, account, environments and
/// settings, exactly like the desktop app's own serve mode does (upstream
/// points serve at the desktop profile; orcad's instance lock makes two
/// runtimes sharing it refuse each other). ORCA_RS_DATA_DIR overrides it.
fn profile_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Ok(custom) = std::env::var("ORCA_RS_DATA_DIR") {
        if !custom.trim().is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    let base = app
        .path()
        .config_dir()
        .map_err(|e| format!("config dir unavailable: {e}"))?;
    Ok(base.join("orca"))
}

fn start_local_runtime(app: &tauri::AppHandle) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let resource_dir = match handle.path().resource_dir() {
            Ok(dir) => dir,
            Err(e) => {
                show_startup_error(&handle, &format!("resource dir unavailable: {e}"));
                return;
            }
        };
        let data_dir = match profile_dir(&handle) {
            Ok(dir) => dir,
            Err(e) => {
                show_startup_error(&handle, &e);
                return;
            }
        };
        let orcad_dir = resource_dir.join("orcad");
        let node = match resolve_pinned_node(&resource_dir, &orcad_dir) {
            Ok(node) => node,
            Err(e) => {
                show_startup_error(&handle, &e);
                return;
            }
        };
        let entry = orcad_dir.join("orcad.js");
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
            Err(e) => show_startup_error(&handle, &e),
        }
    });
}

/// Headless smoke test: ORCA_RS_TEST_SPAWN=1 with ORCA_RS_RESOURCES (a
/// resources root holding orcad/, web/ and runtimes/) and ORCA_RS_DATA_DIR
/// set prints the web client URL the window would open, then kills the
/// runtime.
fn headless_test_requested() -> bool {
    std::env::var("ORCA_RS_TEST_SPAWN").is_ok()
}

fn run_headless_test() {
    let resources = PathBuf::from(std::env::var("ORCA_RS_RESOURCES").unwrap());
    let data_dir = PathBuf::from(std::env::var("ORCA_RS_DATA_DIR").unwrap());
    let orcad_dir = resources.join("orcad");
    let node = resolve_pinned_node(&resources, &orcad_dir).expect("pinned node");
    match spawn_orcad(
        &node,
        &orcad_dir.join("orcad.js"),
        &resources.join("web"),
        &data_dir,
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
