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
//! answers from the local runtime: profile data comes from
//! the same profile-state store daemon-rs serves (the RS
//! profile, imported from the original Orca profile on
//! first run). Nothing is spawned except the app itself;
//! no Node, no server, no pairing for its own machine.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;

static CALL_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

fn log_call(path: &str, args: &[serde_json::Value]) {
    if let Ok(mut slot) = CALL_LOG.lock() {
        if let Some(file) = slot.as_mut() {
            // Args are logged (truncated, single line) because the
            // renderer reports its own crashes through
            // crashReports.recordRendererError — the message only
            // exists in the args.
            let summary = serde_json::to_string(args)
                .unwrap_or_default()
                .replace(['\n', '\r', '\t'], " ");
            let summary: String = summary.chars().take(600).collect();
            let _ = writeln!(file, "{path}\t{}\t{summary}", args.len());
            let _ = file.flush();
        }
    }
}

/// Local state the bridge answers from: the RS profile dir,
/// the settings snapshot read at startup (the same snapshot
/// the shim's synchronous settings read returns), a per-run
/// runtime id for runtime.getStatus, and the Node-style
/// platform string ("win32" / "darwin" / "linux").
struct BridgeState {
    profile_dir: PathBuf,
    settings: serde_json::Value,
    runtime_id: String,
    platform: String,
}

fn domain_or(state: &BridgeState, domain: &str, fallback: serde_json::Value) -> serde_json::Value {
    orca_daemon_rs::profile_state::read_domain(&state.profile_dir, domain).unwrap_or(fallback)
}

fn empty_list() -> serde_json::Value {
    serde_json::json!([])
}

/// The one bridge command: every window.api call arrives
/// here with its dotted path (e.g. "repos.list"). Paths not
/// yet implemented answer null, and the call log shows
/// exactly what the renderer asks for, in order.
#[tauri::command]
fn ipc_invoke(
    app: tauri::AppHandle,
    state: tauri::State<'_, BridgeState>,
    path: String,
    args: Vec<serde_json::Value>,
) -> serde_json::Value {
    log_call(&path, &args);
    match path.as_str() {
        "settings.get" => state.settings.clone(),
        "repos.list" => domain_or(state, "repos", empty_list()),
        "repos.isGitAvailable" => serde_json::json!(
            std::process::Command::new("git")
                .arg("--version")
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false)
        ),
        "app.quit" => {
            app.exit(0);
            serde_json::Value::Null
        }

        // --- Boot-path answers (from the first real run's
        // shim-calls.log, 2026-11-25). Shapes follow the
        // upstream preload API types; lists the local runtime
        // does not have yet answer as empty lists instead of
        // null, which the renderer does not survive.
        "ui.get" => domain_or(state, "ui", serde_json::json!({})),
        "projects.list" => match domain_or(state, "projects", empty_list()) {
            value if value.is_array() => value,
            _ => empty_list(),
        },
        "runtime.getStatus" => serde_json::json!({
            "runtimeId": state.runtime_id,
            "rendererGraphEpoch": 0,
            "graphStatus": "ready",
            "authoritativeWindowId": null,
            "liveTabCount": 0,
            "liveLeafCount": 0,
            "runtimeProtocolVersion": 3,
            "minCompatibleRuntimeClientVersion": 2,
            "capabilities": [],
            "appVersion": env!("CARGO_PKG_VERSION"),
            "hostPlatform": state.platform,
        }),
        "runtime.getTerminalDrivers"
        | "runtime.getBrowserDrivers"
        | "runtime.getTerminalFitOverrides"
        | "runtime.getClientHostedBrowserRows"
        | "runtimeEnvironments.list"
        | "runtimeEnvironments.getStatusSnapshots"
        | "plugins.list"
        | "plugins.listThemes"
        | "plugins.listTerminalThemes"
        | "plugins.listIconThemes"
        | "plugins.takeUpdateReviewNotices"
        | "projects.listHostSetups"
        | "projectGroups.list"
        | "folderWorkspaces.list"
        | "repos.listWslMoved"
        | "repos.listHostCatalogSnapshots"
        | "wslMove.listPendingRendererRewrites"
        | "wslDriveUnc.listPendingRendererRewrites" => empty_list(),
        "session.desktopRelaysVersion" => serde_json::json!(0),
        "onboarding.get" => serde_json::json!({
            "flowVersion": 1,
            "closedAt": null,
            "outcome": null,
            "lastCompletedStep": -1,
            "checklist": {},
        }),
        "keybindings.get" => serde_json::json!({
            "path": "",
            "platform": state.platform,
            "exists": false,
            "overrides": {},
            "commonOverrides": {},
            "platformOverrides": {},
            "diagnostics": [],
        }),
        "orcaProfiles.authStatus" => serde_json::json!({
            "activeProfileId": "",
            "configured": false,
            "state": "unconfigured",
            "persistence": "none",
        }),
        "orcaProfiles.list" => serde_json::json!({
            "status": "unconfigured",
            "auth": {
                "activeProfileId": "",
                "configured": false,
                "state": "unconfigured",
                "persistence": "none",
            },
            "activeProfileId": "",
            "profiles": [],
            "multiProfileUi": false,
        }),
        "plugins.getAutoUpdateState" => serde_json::json!({
            "updated": {},
            "needsReview": {},
        }),
        "jira.status" => serde_json::json!({
            "connected": false,
            "viewer": null,
        }),
        "ssh.importConfig" => serde_json::json!({}),

        _ => serde_json::Value::Null,
    }
}

/// Builds the shim script with the sync boot values baked
/// in (the preload's only synchronous reads: platform info
/// and the settings snapshot).
fn shim_script(settings: &serde_json::Value) -> String {
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
        "settings": settings,
        "appVersion": env!("CARGO_PKG_VERSION"),
    });
    include_str!("shim.js").replace("/*__BOOT__*/ null", &boot.to_string())
}

fn main() {
    let profile_dir = orca_daemon_rs::resolve_profile_dir();
    let settings = orca_daemon_rs::profile_state::read_domain(&profile_dir, "settings")
        .unwrap_or_else(|| serde_json::json!({}));
    let shim = shim_script(&settings);
    let platform = match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        other => other,
    }
    .to_string();
    // A per-run id is all runtime.getStatus needs; it does not
    // have to survive restarts.
    let runtime_id = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("desktop-{:x}-{}", nanos, std::process::id())
    };
    tauri::Builder::default()
        .manage(BridgeState {
            profile_dir,
            settings,
            runtime_id,
            platform,
        })
        .invoke_handler(tauri::generate_handler![ipc_invoke])
        .setup(move |app| {
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
            let _window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("Orca Rust Desktop")
            .inner_size(1440.0, 900.0)
            .min_inner_size(900.0, 600.0)
            .center()
            .initialization_script(&shim)
            .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Orca Rust Desktop");
}
