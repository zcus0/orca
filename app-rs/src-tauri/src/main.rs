#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Orca Rust — the full-Rust desktop app. The daemon
//! (orca-daemon-rs) is linked into this binary and runs
//! in-process on a Tokio runtime in a daemon thread: one
//! binary, one runtime, no Node, nothing spawned. The window
//! shows the web client the daemon itself serves, paired with
//! the in-process daemon via its first-run pairing offer. The
//! daemon uses the separate Orca RS profile, so this app and
//! the original Orca can run at the same time.

use std::path::PathBuf;
use tauri::Manager;

/// Shows a startup failure on the loading page instead of
/// hanging silently.
fn show_startup_error(app: &tauri::AppHandle, message: &str) {
    eprintln!("orca-rust: {message}");
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(js_arg) =
            serde_json::to_string(&format!("Orca Rust failed to start: {message}"))
        {
            let _ = window.eval(format!(
                "document.getElementById('status').textContent = {js_arg}"
            ));
        }
    }
}

/// Starts the in-process daemon and points the window at it.
/// The daemon thread parks forever: the Tokio runtime and the
/// daemon live exactly as long as the app process.
fn start_daemon(app: &tauri::AppHandle) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let web_root = match handle.path().resource_dir() {
            Ok(dir) => dir.join("web"),
            Err(e) => {
                show_startup_error(&handle, &format!("resource dir unavailable: {e}"));
                return;
            }
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(e) => {
                show_startup_error(&handle, &format!("tokio runtime: {e}"));
                return;
            }
        };
        let daemon = match runtime.block_on(orca_daemon_rs::start(orca_daemon_rs::DaemonConfig {
            profile_dir: None,
            port: 0,
            web_root: Some(web_root),
        })) {
            Ok(daemon) => daemon,
            Err(e) => {
                show_startup_error(&handle, &format!("daemon: {e}"));
                return;
            }
        };
        let url = daemon.pairing_url.clone().unwrap_or_else(|| daemon.web_url.clone());
        if let Some(window) = handle.get_webview_window("main") {
            if let Ok(parsed) = url.parse::<tauri::Url>() {
                let _ = window.navigate(parsed);
            }
        }
        // Keep the runtime (and with it the daemon) alive for
        // the life of the process.
        loop {
            std::thread::park();
        }
    });
}

/// Headless smoke test: ORCA_RUST_TEST=1 starts the in-process
/// daemon with ORCA_RUST_TEST_WEB_ROOT as the web root, prints
/// the URL the window would open, and exits.
fn run_headless_test() {
    let web_root = PathBuf::from(std::env::var("ORCA_RUST_TEST_WEB_ROOT").unwrap_or_default());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match runtime.block_on(orca_daemon_rs::start(orca_daemon_rs::DaemonConfig {
        profile_dir: None,
        port: 0,
        web_root: Some(web_root),
    })) {
        Ok(daemon) => {
            let url = daemon.pairing_url.clone().unwrap_or_else(|| daemon.web_url.clone());
            println!("WEB_CLIENT_URL {url}");
        }
        Err(e) => {
            eprintln!("DAEMON_FAILED {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    if std::env::var("ORCA_RUST_TEST").is_ok() {
        run_headless_test();
        return;
    }
    tauri::Builder::default()
        .setup(|app| {
            start_daemon(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Orca Rust")
        .run(|_, _| {});
}
