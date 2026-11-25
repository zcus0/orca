#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Orca Rust Desktop (Fase 4) — the upstream DESKTOP
//! renderer running on the Rust runtime, no server.
//!
//! The window loads the bundled desktop renderer
//! (out/renderer from `pnpm run build:electron-vite`) and a
//! shim injected before any renderer code defines
//! `window.api`, standing in for the Electron preload
//! bridge. Renderer calls land in `ipc_invoke`, which logs
//! every path to shim-calls.log in the app data dir and
//! answers from the local runtime as implementations land.
//! The daemon (orca-daemon-rs) is linked into this binary
//! for the local facilities (profile store, PTYs) the
//! bridge is wired to next; nothing is spawned, no Node.

use std::io::Write;
use std::sync::Mutex;
use tauri::Manager;

static CALL_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn log_call(path: &str, argc: usize) {
    if let Ok(mut slot) = CALL_LOG.lock() {
        if let Some(file) = slot.as_mut() {
            let _ = writeln!(file, "{path}\t{argc}");
            let _ = file.flush();
        }
    }
}

/// The one bridge command: every window.api call arrives
/// here with its dotted path (e.g. "repos.list"). Until a
/// path is implemented against the local runtime it answers
/// null, and the call log shows exactly what the renderer
/// asks for, in the order it asks.
#[tauri::command]
fn ipc_invoke(path: String, args: Vec<serde_json::Value>) -> serde_json::Value {
    log_call(&path, args.len());
    match path.as_str() {
        _ => serde_json::Value::Null,
    }
}

/// Builds the shim script with the sync boot values baked
/// in (the preload's only synchronous reads: platform info
/// and the settings snapshot).
fn shim_script() -> String {
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let boot = serde_json::json!({
        "platform": {
            "platform": platform,
            "osRelease": "",
            "arch": arch,
            "shell": "",
            "displayServer": null,
            "windowMaterial": null,
        },
        "settings": {},
        "appVersion": env!("CARGO_PKG_VERSION"),
    });
    include_str!("shim.js").replace("/*__BOOT__*/ null", &boot.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![ipc_invoke])
        .setup(|app| {
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                if let Ok(file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("shim-calls.log"))
                {
                    *CALL_LOG.lock().unwrap() = Some(file);
                }
            }
            let window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("Orca Rust Desktop")
            .inner_size(1440.0, 900.0)
            .min_inner_size(900.0, 600.0)
            .center()
            .initialization_script(&shim_script())
            .build()?;
            let _ = window;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Orca Rust Desktop");
}
