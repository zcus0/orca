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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

static CALL_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// True while the renderer reports an open tab/worktree
/// (tracked from session.patchEntries). Closing the window
/// with a live session asks for confirmation first, like the
/// original app; closing with nothing open stays instant.
static SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

fn log_call(path: &str, args: &[serde_json::Value]) {
    if let Ok(mut slot) = CALL_LOG.lock() {
        if let Some(file) = slot.as_mut() {
            // Args are logged (truncated, single line) because the
            // renderer reports its own crashes through
            // crashReports.recordRendererError — the message only
            // exists in the args. Crash-report calls keep a much
            // larger slice: their errorStack field carries the
            // full JS stack, which the 600-char cut amputated.
            let limit = if path.starts_with("crashReports.") {
                4000
            } else {
                600
            };
            let summary = serde_json::to_string(args)
                .unwrap_or_default()
                .replace(['\n', '\r', '\t'], " ");
            let summary: String = summary.chars().take(limit).collect();
            let _ = writeln!(file, "{path}\t{}\t{summary}", args.len());
            let _ = file.flush();
        }
    }
}

/// Logs the value a bridge call answered with (truncated,
/// single line), prefixed "->". The 0.4.2 boot died rendering
/// the worktree sidebar on data the bridge itself had served;
/// without the answers in the log, the poisoned value is
/// invisible. Diagnostic spam (startup breadcrumbs, crash
/// reports) is skipped — their inputs are already logged.
fn log_answer(path: &str, value: &serde_json::Value) {
    if path.starts_with("app.startupDiagnostic") || path.starts_with("crashReports.") {
        return;
    }
    if let Ok(mut slot) = CALL_LOG.lock() {
        if let Some(file) = slot.as_mut() {
            let summary = serde_json::to_string(value)
                .unwrap_or_default()
                .replace(['\n', '\r', '\t'], " ");
            let summary: String = summary.chars().take(800).collect();
            let _ = writeln!(file, "-> {path}\t{summary}");
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

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn git_available() -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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
    if path == "session.patchEntries" {
        let active = args
            .first()
            .and_then(|a| a.get("fields"))
            .map(|f| {
                f.get("activeTabId").is_some_and(|v| !v.is_null())
                    || f.get("activeWorktreeId").is_some_and(|v| !v.is_null())
            })
            .unwrap_or(false);
        SESSION_ACTIVE.store(active, Ordering::Relaxed);
    }
    let result = match path.as_str() {
        "settings.get" => state.settings.clone(),
        "repos.list" => domain_or(&state, "repos", empty_list()),
        "repos.isGitAvailable" => serde_json::json!(git_available()),
        "app.quit" => {
            app.exit(0);
            serde_json::Value::Null
        }

        // --- Boot-path answers (from the first real run's
        // shim-calls.log, 2026-11-25). Shapes follow the
        // upstream preload API types; lists the local runtime
        // does not have yet answer as empty lists instead of
        // null, which the renderer does not survive.
        "ui.get" => domain_or(&state, "ui", serde_json::json!({})),
        "projects.list" => match domain_or(&state, "projects", empty_list()) {
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

        // --- Second boot iteration (0.4.1 run's log,
        // 2026-11-25): the boot chain now completes, but the
        // worktree sidebar render dies on
        // "Cannot read properties of undefined (reading
        // 'startsWith')" because session.get answered null.
        // The persisted session lives in the profile-state
        // store under the "workspaceSession" domain (see
        // src/main/persistence/workspace-session-domains.ts);
        // serve it verbatim, with a minimal valid state as
        // fallback (required fields per
        // workspace-session-state-types.ts).
        "session.get" => domain_or(
            &state,
            "workspaceSession",
            serde_json::json!({
                "activeRepoId": null,
                "activeWorktreeId": null,
                "activeTabId": null,
                "tabsByWorktree": {},
                "terminalLayoutsByTabId": {},
            }),
        ),
        "session.listHostIds" => empty_list(),
        // The updater store reads `.state` off getStatus —
        // null crashed it ("reading 'state'"). {state:'idle'}
        // is the valid no-update state; getVersion is a plain
        // string.
        "updater.getStatus" => serde_json::json!({ "state": "idle" }),
        "updater.getVersion" => serde_json::json!(env!("CARGO_PKG_VERSION")),
        "rateLimits.get" | "rateLimits.refresh" => empty_rate_limit_state(),
        // Skill discovery: the settings CLI page and the skill
        // stores read .skills off these results; null crashed
        // the Command line settings check ("reading 'skills'").
        "skills.discover" => serde_json::json!({
            "skills": [],
            "sources": [],
            "scannedAt": now_millis(),
        }),
        "skills.bundledPlan" => serde_json::json!({
            "scope": "global",
            "homeDirectory": std::env::home_dir()
                .map(|h| h.display().to_string())
                .unwrap_or_default(),
            "skills": [],
            "planDigest": "",
        }),
        "speech.getModelStates" => empty_list(),
        "mobile.listDevices" => empty_list(),
        "wsl.isAvailable" => serde_json::json!(false),
        // Caffeinate status-bar segment: it stores this result
        // as its state and renders .mode off it — null crashed
        // the status bar ("reading 'mode'") in 0.4.5.
        "agentAwake.getStatus" => serde_json::json!({ "mode": "off", "active": false }),
        "plugins.statusBarState" => serde_json::json!({}),
        "memory.resourceWindowVisible" => serde_json::json!(false),
        "legacyRelayBridge.listPanes" => empty_list(),
        "preflight.detectAgents" => empty_list(),
        "preflight.refreshAgents" => serde_json::json!({
            "agents": [],
            "addedPathSegments": [],
            "shellHydrationOk": false,
            "pathSource": "sync_seed_only",
            "pathFailureReason": "none",
        }),
        "preflight.check" => serde_json::json!({
            "git": { "installed": git_available() },
            "gh": { "installed": false, "authenticated": false },
        }),
        "avatarGeneration.capability" => serde_json::json!({ "agents": [] }),
        "ssh.listRemovedTargetLabels" => serde_json::json!({}),
        "worktrees.listLineage" => serde_json::json!({
            "lineage": {},
            "workspaceLineage": {},
            "crossStoreLineage": {},
        }),
        "cache.getGitHub" => serde_json::json!({ "pr": {}, "issue": {} }),
        // runtime.call routes RPC methods to the local
        // runtime; the boot path asks for the bots catalog,
        // whose result shapes are {bots:[...]} / {groups:[]}
        // (component-fixtures/fixture-bots.ts). Other methods
        // get an empty object rather than null for now.
        "runtime.call" => {
            let method = args
                .first()
                .and_then(|a| a.get("method"))
                .and_then(|m| m.as_str())
                .unwrap_or("");
            match method {
                "bots.list" => serde_json::json!({ "bots": [] }),
                "bots.groups.list" => serde_json::json!({ "groups": [] }),
                _ => serde_json::json!({}),
            }
        }
        "linear.status" => serde_json::json!({
            "connected": false,
            "viewer": null,
        }),
        // Plain booleans the boot path probes.
        "app.holdsStructuredAgentSessions"
        | "ui.isMaximized"
        | "backgroundWorker.isPaused"
        | "agentStatus.hasRestartOffers"
        | "pwsh.isAvailable"
        | "gitBash.isAvailable" => serde_json::json!(false),
        // More boot-path lists that must not be null.
        "wsl.listDistros"
        | "ssh.listTargets"
        | "runtime.getBrowserRemoteViewerPages"
        | "runtimeEnvironments.portForwards.list"
        | "runtimeEnvironments.portForwards.takeRestoredMoves"
        | "ephemeralVm.listPendingCheckouts"
        | "ephemeralVm.listRuntimes"
        | "plugins.takeRequiredPluginFailures" => empty_list(),

        _ => serde_json::Value::Null,
    };
    log_answer(&path, &result);
    result
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

/// Upstream's default global settings, generated from
/// src/shared/settings/default-global-settings.ts via
/// getDefaultSettings() (src/shared/orca-profiles/constants.ts)
/// and committed as default-settings.json. The real main
/// process always merges the stored settings over these
/// defaults, so settings.get never returns a partial object;
/// the renderer dereferences nested fields (notifications.
/// enabled, terminalThemeDark.startsWith, ...) unconditionally
/// and crashes on a bare {} — exactly the 0.4.0–0.4.3 boot
/// failure.
fn default_settings() -> serde_json::Value {
    serde_json::from_str(include_str!("../default-settings.json"))
        .unwrap_or_else(|_| serde_json::json!({}))
}

/// Recursive merge: values from `over` win; when both sides
/// are objects their keys merge, so a stored partial nested
/// object still inherits the default's sibling fields.
fn merge_json(base: &serde_json::Value, over: &serde_json::Value) -> serde_json::Value {
    match (base, over) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            let mut out = b.clone();
            for (k, v) in o {
                let merged = match out.get(k) {
                    Some(existing) => merge_json(existing, v),
                    None => v.clone(),
                };
                out.insert(k.clone(), merged);
            }
            serde_json::Value::Object(out)
        }
        _ => over.clone(),
    }
}

/// The settings snapshot the bridge serves: stored profile
/// settings deep-merged over the upstream defaults. When the
/// profile never chose a workspace dir, point it at the real
/// home directory's orca/workspaces like getDefaultSettings
/// does, instead of the path baked into the generated JSON.
fn effective_settings(profile_dir: &std::path::Path) -> serde_json::Value {
    let stored = orca_daemon_rs::profile_state::read_domain(profile_dir, "settings");
    let stored_has_workspace = stored
        .as_ref()
        .and_then(|s| s.get("workspaceDir"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    let mut merged = match &stored {
        Some(s) => merge_json(&default_settings(), s),
        None => default_settings(),
    };
    if !stored_has_workspace {
        if let Some(home) = std::env::home_dir() {
            let sep = std::path::MAIN_SEPARATOR;
            let dir = format!("{}{}orca{}workspaces", home.display(), sep, sep);
            if let Some(obj) = merged.as_object_mut() {
                obj.insert("workspaceDir".into(), serde_json::json!(dir));
            }
        }
    }
    merged
}

/// The empty rate-limit state, mirroring upstream's
/// createEmptyRateLimitState() (src/shared/agent-usage/
/// rate-limits/rate-limit-state-factory.ts). The status bar's
/// switcher menu reads .codex/.claude off this object, so a
/// null answer crashes it.
fn empty_rate_limit_state() -> serde_json::Value {
    serde_json::json!({
        "claude": null,
        "codex": null,
        "gemini": null,
        "opencodeGo": null,
        "kimi": null,
        "antigravity": null,
        "minimax": null,
        "grok": null,
        "cursor": null,
        "zcode": null,
        "muse": null,
        "minimaxCookieConfigured": false,
        "minimaxApiKeyConfigured": false,
        "opencodeGoApiKeyConfigured": false,
        "grokAuthConfigured": false,
        "cursorAuthConfigured": false,
        "zcodePlanApiKeyConfigured": false,
        "claudeTarget": { "runtime": "host", "wslDistro": null },
        "codexTarget": { "runtime": "host", "wslDistro": null },
        "inactiveClaudeAccounts": [],
        "inactiveCodexAccounts": [],
        "antigravityAccounts": [],
    })
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

/// In-app update check (Windows): compare this build against
/// the newest installer published in the desktop-dev release;
/// if a newer one exists, ask natively, then download the
/// setup exe, launch it (it upgrades in place) and exit.
/// Every failure is silent — an offline or rate-limited
/// launch must never be disturbed. Runs on a spawned thread.
#[cfg(target_os = "windows")]
fn check_for_update(app: tauri::AppHandle) {
    use tauri_plugin_dialog::MessageDialogButtons;
    let client = match reqwest::blocking::Client::builder()
        .user_agent("orca-rust-desktop-updater")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let release: serde_json::Value = match client
        .get("https://api.github.com/repos/zcus0/orca/releases/tags/desktop-dev")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
    {
        Ok(v) => v,
        Err(_) => return,
    };
    let current = parse_version(env!("CARGO_PKG_VERSION")).unwrap_or((0, 0, 0));
    let mut best: Option<((u32, u32, u32), String, String)> = None;
    if let Some(assets) = release.get("assets").and_then(|a| a.as_array()) {
        for asset in assets {
            let name = asset.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let Some(vstr) = name
                .strip_prefix("Orca.Rust.Desktop_")
                .and_then(|rest| rest.strip_suffix("_x64-setup.exe"))
            else {
                continue;
            };
            let Some(v) = parse_version(vstr) else { continue };
            if v > current && best.as_ref().is_none_or(|(bv, _, _)| v > *bv) {
                if let Some(url) = asset
                    .get("browser_download_url")
                    .and_then(|u| u.as_str())
                {
                    best = Some((v, vstr.to_string(), url.to_string()));
                }
            }
        }
    }
    let Some((_, vstr, url)) = best else { return };
    let yes = app
        .dialog()
        .message(format!(
            "Orca Rust Desktop {vstr} is available — you have {}. Download and install the update now? The app will close and the installer will take over.",
            env!("CARGO_PKG_VERSION")
        ))
        .title("Update available")
        .buttons(MessageDialogButtons::YesNo)
        .blocking_show();
    if !yes {
        return;
    }
    let dest = std::env::temp_dir().join(format!("OrcaRustDesktop-{vstr}-setup.exe"));
    let bytes = match client
        .get(&url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
    {
        Ok(b) => b,
        Err(_) => return,
    };
    if std::fs::write(&dest, &bytes).is_err() {
        return;
    }
    if std::process::Command::new(&dest).spawn().is_ok() {
        app.exit(0);
    }
}

fn main() {
    let profile_dir = orca_daemon_rs::resolve_profile_dir();
    let settings = effective_settings(&profile_dir);
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
        // Single instance: a second launch (or the installer
        // relaunching the app while it runs) focuses the
        // existing window instead of spawning another one
        // that piles up in alt-tab. Must be the first plugin.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if SESSION_ACTIVE.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let app = window.app_handle().clone();
                    std::thread::spawn(move || {
                        let yes = app
                            .dialog()
                            .message(
                                "You have an open workspace session. Quit Orca Rust Desktop anyway?",
                            )
                            .title("Quit Orca Rust Desktop?")
                            .buttons(tauri_plugin_dialog::MessageDialogButtons::YesNo)
                            .blocking_show();
                        if yes {
                            app.exit(0);
                        }
                    });
                }
            }
        })
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
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("shim-calls.log"))
                {
                    // Run separator: the log appends across
                    // runs and versions, so each launch marks
                    // where its calls begin.
                    let _ = writeln!(
                        file,
                        "=== orca-rust-desktop {} start ===",
                        env!("CARGO_PKG_VERSION")
                    );
                    let _ = file.flush();
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
            // Background update check, a few seconds after the
            // window is up so the prompt never fights first paint.
            #[cfg(target_os = "windows")]
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    check_for_update(handle);
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Orca Rust Desktop");
}
