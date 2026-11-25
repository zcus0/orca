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
static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Shared key for the debug-report endpoint. It only gates
/// random spam: the endpoint accepts a small JSON, stores it
/// as a file on the user's own server, and does nothing else.
const DEBUG_REPORT_KEY: &str = "odr-7f3a9c51e8b44d2a9f0e5c6d81b3a4f7";
const DEBUG_REPORT_URL: &str = "https://orca-debug.zcus.dev/report";

/// Self-debugging: when the renderer reports a crash, upload
/// the crash payload plus the tail of shim-calls.log to the
/// debug endpoint on the user's server, where the agent can
/// read it directly — no more manual log pastes. Fire and
/// forget on a spawned thread; every failure is silent.
fn upload_crash_report(crash_args: &[serde_json::Value]) {
    let log_tail = LOG_PATH
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| {
            let lines: Vec<&str> = text.lines().collect();
            let start = lines.len().saturating_sub(300);
            lines[start..].join("\n")
        })
        .unwrap_or_default();
    let payload = serde_json::json!({
        "app": "orca-rust-desktop",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "ts": now_millis(),
        "crash": crash_args,
        "logTail": log_tail,
    });
    std::thread::spawn(move || {
        let client = match reqwest::blocking::Client::builder()
            .user_agent("orca-rust-desktop-debug")
            .timeout(std::time::Duration::from_secs(15))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = client
            .post(DEBUG_REPORT_URL)
            .header("X-Debug-Key", DEBUG_REPORT_KEY)
            .json(&payload)
            .send();
    });
}

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
    settings: Mutex<serde_json::Value>,
    stored_settings: Mutex<serde_json::Value>,
    runtime_id: String,
    platform: String,
    rpc: Mutex<orca_daemon_rs::rpc::Rpc>,
    rpc_seq: Mutex<u64>,
    telemetry_opt_in: Mutex<Option<bool>>,
}

/// Telemetry consent lives in its own profile-state domain
/// ("telemetryConsent": {"optIn": bool}); the cache slot
/// starts unset and loads from the store on first read.
fn telemetry_opt_in(state: &BridgeState) -> bool {
    if let Ok(settings) = state.settings.lock() {
        if let Some(value) = settings
            .get("telemetry")
            .and_then(|t| t.get("optedIn"))
            .and_then(serde_json::Value::as_bool)
        {
            return value;
        }
    }
    let mut slot = state.telemetry_opt_in.lock().unwrap();
    if let Some(value) = *slot {
        return value;
    }
    let stored = domain_or(state, "telemetryConsent", serde_json::json!({}));
    let value = stored
        .get("optIn")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    *slot = Some(value);
    value
}

fn set_telemetry_opt_in(state: &BridgeState, opted_in: bool) {
    *state.telemetry_opt_in.lock().unwrap() = Some(opted_in);
    apply_settings_patch(
        state,
        &serde_json::json!({ "telemetry": { "optedIn": opted_in } }),
    );
    let _ = orca_daemon_rs::profile_state::write_domain(
        &state.profile_dir,
        "telemetryConsent",
        &serde_json::json!({ "optIn": opted_in }),
    );
}

/// Merge a patch into the stored settings document, persist
/// it, and refresh the effective snapshot. The single write
/// path for settings.set and for bridge calls that own a
/// settings subtree (the Privacy pane's toggle reads
/// settings.telemetry.optedIn, so telemetrySetOptIn must
/// land here too or the switch never moves).
fn apply_settings_patch(state: &BridgeState, patch: &serde_json::Value) {
    let merged_stored = {
        let mut stored = state
            .stored_settings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let merged = merge_json(&stored, patch);
        *stored = merged.clone();
        merged
    };
    let _ = orca_daemon_rs::profile_state::write_domain(
        &state.profile_dir,
        "settings",
        &merged_stored,
    );
    let effective = effective_from_stored(Some(&merged_stored));
    if let Ok(mut settings) = state.settings.lock() {
        *settings = effective;
    }
}

/// The Uninstall section's plan when this runtime installed
/// nothing outside its own app folder: every cleanup step is
/// already absent, so the section renders its empty state
/// instead of spinning on a null plan.
fn uninstall_plan(state: &BridgeState) -> serde_json::Value {
    let install_kind = match state.platform.as_str() {
        "win32" => "windows-installer",
        "darwin" => "mac-app",
        _ => "linux-appimage",
    };
    serde_json::json!({
        "installKind": install_kind,
        "agents": [],
        "cliCommand": null,
        "backgroundService": null,
        "hookScripts": null,
        "hosts": [],
        "terminalDaemon": null,
        "otherOrcaBuildName": null,
        "appPath": null,
        "removeAppCommand": null,
    })
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
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        let mut cmd = std::process::Command::new("git");
        cmd.arg("--version");
        // CREATE_NO_WINDOW: this probe runs on renderer focus /
        // workspace refresh calls, and a console window flashing
        // into alt-tab on every probe reads as the app spawning
        // processes. Probe once, invisibly, and cache it.
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.output().map(|out| out.status.success()).unwrap_or(false)
    })
}

/// Forwards one runtime.call to the in-process daemon-rs RPC
/// dispatch and unwraps its response envelope. None when the
/// daemon does not implement the method (or errors), so the
/// caller can fall back to the desktop-shaped stubs.
fn dispatch_runtime(
    state: &BridgeState,
    method: &str,
    params: serde_json::Value,
) -> Option<serde_json::Value> {
    let id = {
        let mut seq = state.rpc_seq.lock().ok()?;
        *seq += 1;
        format!("desktop-{}", *seq)
    };
    let request = serde_json::json!({ "id": id, "method": method, "params": params }).to_string();
    let ctx = orca_daemon_rs::rpc::Ctx {
        device_id: None,
        device_token: None,
        transcript_hash_b64: None,
    };
    let response = state.rpc.lock().ok()?.handle(&request, &ctx)?;
    let parsed: serde_json::Value = serde_json::from_str(&response).ok()?;
    if parsed.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        parsed.get("result").cloned()
    } else {
        None
    }
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
    if path == "crashReports.recordRendererError" {
        upload_crash_report(&args);
    }
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
        "settings.get" => state
            .settings
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| serde_json::json!({})),
        // Settings writes used to be discarded, so every choice
        // reset on restart. Now: merge the patch into the stored
        // settings document, persist it in upstream's format,
        // and serve the re-merged effective snapshot.
        "settings.set" => {
            if let Some(patch) = args.first().filter(|p| p.is_object()) {
                apply_settings_patch(&state, patch);
            }
            serde_json::Value::Null
        }
        "onboarding.update" => {
            if let Some(value) = args.first() {
                orca_daemon_rs::profile_state::write_domain(
                    &state.profile_dir,
                    "onboarding",
                    value,
                );
            }
            serde_json::Value::Null
        }
        "session.patchEntries" => {
            if let Some(patch) = args.first() {
                let mut session = domain_or(
                    &state,
                    "workspaceSession",
                    serde_json::json!({
                        "activeRepoId": null,
                        "activeWorktreeId": null,
                        "activeTabId": null,
                        "tabsByWorktree": {},
                        "terminalLayoutsByTabId": {},
                    }),
                );
                if let (Some(obj), Some(fields)) = (
                    session.as_object_mut(),
                    patch.get("fields").and_then(|f| f.as_object()),
                ) {
                    for (k, v) in fields {
                        obj.insert(k.clone(), v.clone());
                    }
                    if let Some(entries) = patch.get("entries").and_then(|e| e.as_object()) {
                        if !entries.is_empty() {
                            let slot = obj
                                .entry("entries".to_string())
                                .or_insert_with(|| serde_json::json!({}));
                            if let Some(slot_obj) = slot.as_object_mut() {
                                for (k, v) in entries {
                                    slot_obj.insert(k.clone(), v.clone());
                                }
                            }
                        }
                    }
                }
                orca_daemon_rs::profile_state::write_domain(
                    &state.profile_dir,
                    "workspaceSession",
                    &session,
                );
            }
            serde_json::Value::Null
        }
        "cache.setGitHub" => {
            if let Some(cache) = args.first().and_then(|a| a.get("cache")) {
                orca_daemon_rs::profile_state::write_domain(
                    &state.profile_dir,
                    "githubCache",
                    cache,
                );
            }
            serde_json::Value::Null
        }
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
        "onboarding.get" => domain_or(
            &state,
            "onboarding",
            serde_json::json!({
                "flowVersion": 1,
                "closedAt": null,
                "outcome": null,
                "lastCompletedStep": -1,
                "checklist": {},
            }),
        ),
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
        // --- Page-surface sweep (0.5.2, from the 0.5.0 log):
        // the Settings browser section does .find() on the
        // session profiles list — null crashed the whole
        // Settings page. These are the empty/no-cloud shapes
        // for the pages that read them (Bots, Skills, Shared
        // links, Settings), each pinned from its upstream type.
        "browser.sessionListProfiles" => empty_list(),
        "browser.sessionDetectBrowsers" => empty_list(),
        "skills.listOwnedShares" => serde_json::json!({
            "status": "ok",
            "value": [],
        }),
        "mobile.listNetworkInterfaces" => serde_json::json!({ "interfaces": [] }),
        "mobile.getRelayStatus" => serde_json::json!({ "status": "offline" }),
        "cli.getInstallStatus" => serde_json::json!({
            "platform": state.platform,
            "commandName": "orca",
            "commandPath": null,
            "pathDirectory": null,
            "pathConfigured": null,
            "launcherPath": null,
            "installMethod": null,
            "supported": false,
            "state": "unsupported",
            "currentTarget": null,
            "unsupportedReason": "platform_not_supported",
            "detail": null,
        }),
        "app.getIdentity" => serde_json::json!({
            "name": "Orca Rust Desktop",
            "isDev": false,
            "devLabel": null,
            "devBranch": null,
            "devWorktreeName": null,
            "devRepoRoot": null,
            "dockBadgeLabel": null,
        }),
        "gh.rateLimit" => serde_json::json!({
            "ok": false,
            "error": "GitHub CLI is not available",
        }),
        "gl.rateLimit" => serde_json::json!({
            "ok": false,
            "error": "GitLab is not configured",
        }),
        "pty.management.listSessions" => empty_list(),
        // --- Settings sweep (0.5.3, from the first real
        // crash uploads): the Plugins section crashed on
        // .filter() because listMarketplacePlugins was null;
        // the remote-server section polls pending migrations;
        // the Privacy toggle never stuck because the consent
        // state read was null.
        "plugins.listMarketplacePlugins" => empty_list(),
        "plugins.listMarketplaces" => empty_list(),
        "plugins.refreshMarketplaces" => empty_list(),
        "runtimeEnvironments.managedOrcad.listPendingMigrations" => empty_list(),
        "diagnostics.getStatus" => serde_json::json!({
            "localFileEnabled": false,
            "bundleEnabled": false,
            "traceFilePath": "",
            "traceFamilySize": 0,
            "disabledReason": "orca_telemetry_disabled",
        }),
        "telemetryGetConsentState" => {
            if telemetry_opt_in(&state) {
                serde_json::json!({ "effective": "enabled" })
            } else {
                serde_json::json!({
                    "effective": "disabled",
                    "reason": "user_opt_out",
                })
            }
        }
        "telemetrySetOptIn" => {
            let opted_in = args
                .first()
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            set_telemetry_opt_in(&state, opted_in);
            serde_json::Value::Null
        }
        // --- Accounts + usage (0.6.0): the Settings page is
        // one boundary — the Accounts section replaced its
        // state with the null list() result and crashed the
        // whole page on .accounts (every Settings section
        // read as "This page hit an error"). Empty states:
        "claudeAccounts.list" => serde_json::json!({
            "accounts": [],
            "activeAccountId": null,
        }),
        "codexAccounts.list" => serde_json::json!({
            "accounts": [],
            "activeAccountId": null,
            "activeAccountIdsByRuntime": { "host": null, "wsl": {} },
        }),
        "claudeUsage.getScanState" => serde_json::json!({
            "enabled": true,
            "isScanning": false,
            "lastScanStartedAt": null,
            "lastScanCompletedAt": null,
            "lastScanError": null,
            "hasAnyClaudeData": false,
        }),
        "codexUsage.getScanState" => serde_json::json!({
            "enabled": true,
            "isScanning": false,
            "lastScanStartedAt": null,
            "lastScanCompletedAt": null,
            "lastScanError": null,
            "hasAnyCodexData": false,
        }),
        "openCodeUsage.getScanState" => serde_json::json!({
            "enabled": true,
            "isScanning": false,
            "lastScanStartedAt": null,
            "lastScanCompletedAt": null,
            "lastScanError": null,
            "hasAnyOpenCodeData": false,
        }),
        "museUsage.getScanState" => serde_json::json!({
            "enabled": true,
            "isScanning": false,
            "lastScanStartedAt": null,
            "lastScanCompletedAt": null,
            "lastScanError": null,
            "hasAnyMuseData": false,
        }),
        // --- Advanced page (0.6.0): the Uninstall section
        // spun on "Checking what Orca installed…" because
        // getPlan was null; diagnostics no longer reports a
        // disabledReason (it rendered as a hard env block
        // and locked the section's controls).
        "orcaUninstall.getPlan" => uninstall_plan(&state),
        "orcaUninstall.runStep" => uninstall_plan(&state),
        "diagnostics.getStatus" => serde_json::json!({
            "localFileEnabled": true,
            "bundleEnabled": true,
            "traceFilePath": "",
            "traceFamilySize": 0,
        }),
        "diagnostics.collectBundle" => serde_json::json!({
            "bundleSubmissionId": "local-bundle",
            "bytes": 0,
            "spanCount": 0,
        }),
        "diagnostics.uploadBundle" => serde_json::json!({ "canceled": true }),
        "cache.getGitHub" => domain_or(
            &state,
            "githubCache",
            serde_json::json!({ "pr": {}, "issue": {} }),
        ),
        // runtime.call routes RPC methods to the local
        // runtime. Desktop-catalog methods the daemon does not
        // implement keep their shaped stubs; everything else is
        // forwarded to the in-process daemon-rs dispatch
        // (status, repos, session graph, terminals, agent
        // sessions, pairing) — a real local runtime, no server.
        "runtime.call" => {
            let method = args
                .first()
                .and_then(|a| a.get("method"))
                .and_then(|m| m.as_str())
                .unwrap_or("");
            match method {
                "bots.list" => serde_json::json!({ "bots": [] }),
                "bots.groups.list" => serde_json::json!({ "groups": [] }),
                // Bots app-connection states, shapes pinned
                // from the renderer's own fixtures: no cloud
                // apps are connected on the local runtime.
                "google.status" => serde_json::json!({
                    "client": null,
                    "accounts": [],
                    "bots": [],
                }),
                "bots.linear.state" => serde_json::json!({
                    "ok": true,
                    "value": { "installUrl": "", "workspaces": [] },
                }),
                "bots.github.state" => serde_json::json!({
                    "ok": true,
                    "value": {
                        "installUrl": "",
                        "account": null,
                        "installations": [],
                        "defaultBotId": null,
                    },
                }),
                "bots.share.status" => serde_json::json!({
                    "ok": true,
                    "result": { "status": "ok", "value": [] },
                }),
                _ => {
                    let params = args
                        .first()
                        .and_then(|a| a.get("params"))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    dispatch_runtime(&state, method, params)
                        .unwrap_or_else(|| serde_json::json!({}))
                }
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

/// The effective settings served to the renderer: the stored
/// settings document deep-merged over the upstream defaults.
/// When the profile never chose a workspace dir, point it at
/// the real home directory's orca/workspaces like
/// getDefaultSettings does, instead of the path baked into
/// the generated JSON.
fn effective_from_stored(stored: Option<&serde_json::Value>) -> serde_json::Value {
    let stored_has_workspace = stored
        .and_then(|s| s.get("workspaceDir"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty());
    let mut merged = match stored {
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
/// Updater activity goes into the same bridge log the crash
/// uploads carry, so a silent update failure is diagnosable
/// from the next crash report instead of invisible.
fn updater_log(msg: &str) {
    if let Ok(mut slot) = CALL_LOG.lock() {
        if let Some(file) = slot.as_mut() {
            use std::io::Write;
            let _ = writeln!(file, "updater\t{msg}");
        }
    }
}

#[cfg(target_os = "windows")]
fn check_for_update(app: tauri::AppHandle) {
    use tauri_plugin_dialog::MessageDialogButtons;
    updater_log(&format!(
        "check start (current {})",
        env!("CARGO_PKG_VERSION")
    ));
    let client = match reqwest::blocking::Client::builder()
        .user_agent("orca-rust-desktop-updater")
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            updater_log(&format!("client build failed: {e}"));
            return;
        }
    };
    let release: serde_json::Value = match client
        .get("https://api.github.com/repos/zcus0/orca/releases/tags/desktop-dev")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
    {
        Ok(v) => v,
        Err(e) => {
            updater_log(&format!("release fetch failed: {e}"));
            return;
        }
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
    let Some((_, vstr, url)) = best else {
        updater_log("no newer version found");
        return;
    };
    updater_log(&format!("found {vstr}, asking user"));
    // The prompt runs on the main thread (the platform-correct
    // owner for a modal dialog); this worker waits for the
    // answer with a timeout so a stuck dialog cannot wedge
    // the update loop.
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let dialog_app = app.clone();
    let dialog_version = vstr.clone();
    let shown = app.run_on_main_thread(move || {
        let mut builder = dialog_app
            .dialog()
            .message(format!(
                "Orca Rust Desktop {dialog_version} is available — you have {}. Download and install the update now? The app will close and the installer will take over.",
                env!("CARGO_PKG_VERSION")
            ))
            .title("Update available")
            .buttons(MessageDialogButtons::YesNo);
        if let Some(window) = dialog_app.get_webview_window("main") {
            builder = builder.parent(&window);
        }
        let yes = builder.blocking_show();
        let _ = tx.send(yes);
    });
    let yes = match shown {
        Ok(()) => rx
            .recv_timeout(std::time::Duration::from_secs(600))
            .unwrap_or_else(|_| {
                updater_log("dialog answer timed out");
                false
            }),
        Err(e) => {
            updater_log(&format!("dialog dispatch failed: {e}"));
            false
        }
    };
    updater_log(&format!("user answer: {yes}"));
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
        Err(e) => {
            updater_log(&format!("download failed: {e}"));
            return;
        }
    };
    updater_log(&format!("downloaded {} bytes", bytes.len()));
    if let Err(e) = std::fs::write(&dest, &bytes) {
        updater_log(&format!("installer write failed: {e}"));
        return;
    }
    match std::process::Command::new(&dest).spawn() {
        Ok(_) => {
            updater_log("installer launched, exiting");
            app.exit(0);
        }
        Err(e) => updater_log(&format!("installer launch failed: {e}")),
    }
}

fn main() {
    let profile_dir = orca_daemon_rs::resolve_profile_dir();
    let stored_settings =
        orca_daemon_rs::profile_state::read_domain(&profile_dir, "settings")
            .unwrap_or_else(|| serde_json::json!({}));
    let settings = effective_from_stored(Some(&stored_settings));
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
    // The in-process local runtime: daemon-rs's RPC dispatch
    // over the same RS profile, with its own PTY manager and
    // session graph. No port, no server — runtime.call invokes
    // it directly.
    let rpc = {
        use std::sync::Arc;
        let registry = Arc::new(Mutex::new(orca_daemon_rs::registry::Registry::load(
            profile_dir.clone(),
        )));
        let pty = Arc::new(Mutex::new(orca_daemon_rs::pty::PtyManager::new()));
        let graph = Arc::new(Mutex::new(orca_daemon_rs::graph::Graph::new()));
        orca_daemon_rs::rpc::Rpc::new(
            runtime_id.clone(),
            registry,
            profile_dir.clone(),
            pty,
            graph,
        )
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
            settings: Mutex::new(settings),
            stored_settings: Mutex::new(stored_settings),
            runtime_id,
            platform,
            rpc: Mutex::new(rpc),
            rpc_seq: Mutex::new(0),
            telemetry_opt_in: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![ipc_invoke])
        .setup(move |app| {
            if let Ok(dir) = app.path().app_data_dir() {
                let _ = std::fs::create_dir_all(&dir);
                let log_path = dir.join("shim-calls.log");
                *LOG_PATH.lock().unwrap() = Some(log_path.clone());
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
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
            // Background update checks: first a few seconds
            // after the window is up so the prompt never
            // fights first paint, then every 6 hours so a
            // long-running app still learns about releases.
            #[cfg(target_os = "windows")]
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    loop {
                        check_for_update(handle.clone());
                        std::thread::sleep(std::time::Duration::from_secs(6 * 60 * 60));
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Orca Rust Desktop");
}
