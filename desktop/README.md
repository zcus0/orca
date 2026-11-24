# Orca RS — desktop (Tauri)

A lightweight desktop build of Orca: a [Tauri](https://tauri.app) shell
(Rust + the operating system's webview) instead of Electron, with the real
Orca runtime running **locally on this machine**.

## How it works

The installer bundles three resources next to the app binary:

- `orcad/` — the Orca runtime bundle (`pnpm build:orcad`)
- `web/` — the Orca web client (`pnpm build:web`)
- `runtimes/node-<sha256>/` — the exact Node runtime the orcad bundle is
  pinned to (staged by `build:orcad` next to the slot; orcad refuses to
  start without it)

On launch, the Rust shell resolves the pinned runtime from the slot's
`.server-target` / `.runtime-node` markers, spawns it on `orcad.js --port 0
--bind 127.0.0.1 --json --web-client-root web/` with `ORCA_USER_DATA`
pointed at a per-user data directory, reads the `orca_server_ready` line,
and navigates the window to the reported `webClientUrl` (which carries the
pairing offer, so the client pairs with the local runtime automatically).
Projects, terminals and agents run locally; remote Orca servers can still
be paired from inside the client. Closing the app stops the runtime it
started. If startup fails, the loading page shows the error and orcad's
stderr is kept in `runtime.log` inside the app data dir.

The client UI is the web-client feature set. Features that exist only
through the Electron preload bridge (integrated browser tabs, emulator,
native dialogs) are not part of this build.

## Downloads

Every push to `main` rebuilds and republishes the **dev** prerelease on
GitHub Releases; pushing a `v*` tag cuts a versioned release. Assets:

- Windows: NSIS installer `.exe` and `.msi`
- Linux: `.AppImage` and `.deb`
- macOS: `.dmg`

Builds are unsigned. On Windows, SmartScreen will warn — choose
"More info" → "Run anyway". On macOS, right-click the app → Open.

## Local build

```sh
# from the repository root: build the runtime and client for your platform
pnpm install --frozen-lockfile
pnpm -C mobile install --frozen-lockfile
pnpm build:web
pnpm build:orcad

# assemble the bundled resources (CI does the same, plus downloads Node)
mkdir -p desktop/resources
cp -r out/web desktop/resources/web
cp -r out/orcad desktop/resources/orcad
cp "$(which node)" desktop/resources/node        # node.exe on Windows

cd desktop
npm install
npx tauri icon ../resources/build/icon.png   # generates src-tauri/icons/
npx tauri build                              # or: npx tauri dev
```

Linux build dependencies (Debian/Ubuntu): `libwebkit2gtk-4.1-dev`,
`libappindicator3-dev`, `librsvg2-dev`, `patchelf`.

Headless smoke test of the runtime supervisor (no display needed):

```sh
ORCA_RS_TEST_SPAWN=1 \
ORCA_RS_NODE=desktop/resources/node \
ORCA_RS_ORCAD_ENTRY=desktop/resources/orcad/orcad.js \
ORCA_RS_WEB_DIR=desktop/resources/web \
ORCA_RS_DATA_DIR=/tmp/orca-rs-test \
  desktop/src-tauri/target/release/orca-rs-desktop
# prints: WEB_CLIENT_URL http://127.0.0.1:<port>/web-index.html#pairing=...
```
