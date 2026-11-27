# Orca Shell (shell-swap variant)

His 2026-11-28 direction: pull the latest upstream Orca,
rebuild the shell as Tauri, **keep the runtime** — upstream's
own orcad, upstream's own profile, upstream's data. Only the
Electron shell goes away.

## What this is

A copy of `app-desktop/` (the Fase 4 bridge: shim, settings
machinery, updater, debug logging, window controls) retargeted:

- Identity: productName "Orca Shell", identifier
  `dev.zcus.orca.shell` — installable beside both Orca and
  Orca Rust Desktop.
- Profile: the ORIGINAL Orca profile dir (`%APPDATA%\orca`
  on Windows, `~/Library/Application Support/orca` on macOS,
  `$XDG_CONFIG_HOME/orca` on Linux), overridable with
  `ORCA_SHELL_PROFILE`. No RS import, no separate identity.
- Base: upstream main merged 2026-11-28 (803 commits, to
  5f27429c3); the desktop renderer builds clean from it and
  the default-settings key set is unchanged (257 keys).

## Status

- The E2EE client exists and is proven: `daemon-rs`'s
  `client::RuntimeClient` paired with a real upstream
  orcad serve and answered `status.get` / `repo.list`
  (proof binary: `daemon-rs/src/bin/orca-client-test.rs`).
- The shell wires it in: on startup it spawns the bundled
  orcad in serve mode against the real profile (pinned
  Node resolved from the slot markers), pairs, and routes
  `runtime.call` to the serve first — the in-process
  daemon-rs RPC remains as fallback. The orcad child is
  killed on app exit so the profile lock is released.
- CI: `.github/workflows/orca-shell-release.yml` builds
  renderer + orcad + web client, bundles all three plus
  the pinned runtimes, and publishes `tauri-v*` tags as
  versioned releases (dispatch → rolling `shell-dev`).

## What remains

1. **Terminal/pty domain**: the desktop renderer's
   terminals speak the daemon's v62 stream protocol; over
   the serve link they must ride the client's binary
   frames (the client currently surfaces text RPC only).
2. **Server-pushed events**: `runtime.subscribe` events
   from the serve are not yet forwarded into the shim's
   `on*` subscriptions.
3. First-release shakeout: bridge gaps the new upstream
   renderer hits will arrive via the same crash-upload
   channel as the Fase 4 line (app name `orca-shell`).
