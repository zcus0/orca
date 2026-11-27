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

## What remains before this is real

1. **orcad supervision**: spawn the bundled orcad in serve
   mode on a loopback port with the pinned Node runtime —
   the supervisor pattern from the frozen `desktop/` app
   (0.2.2) carries over; CI must bundle the orcad slot +
   `out/runtimes` the same way that line did.
2. **E2EE client**: `runtime.call` currently still routes
   to the in-process daemon-rs placeholder. The real target
   is the spawned orcad's WS RPC, which needs the client
   half of the pairing protocol (daemon-rs has the host
   half; the E2E test client proves the wire format).
3. **Terminal/pty domain**: same open item as Fase 4 — the
   desktop renderer's terminals speak to the daemon's v62
   socket through the main process upstream; here they
   must ride the serve connection like upstream's own
   remote mode does.

Until 1–2 land, this app is a scaffold: it boots the
desktop UI against the real profile's stored state, but
agent execution is not yet upstream's.
