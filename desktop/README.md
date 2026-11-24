# Orca RS — desktop shell (Tauri)

A lightweight desktop shell for Orca, built with [Tauri](https://tauri.app)
(Rust + the operating system's webview) instead of Electron.

The window loads the Orca web client from **https://orca.zcus.dev**. All
sessions, terminals and agents run on the remote Orca server — this app is
only the shell, so it uses a fraction of the RAM of the Electron build.
Pairing works exactly like in a browser: open the app, sign in, and paste
the pairing link offered by your Orca server.

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
cd desktop
npm install
npx tauri icon ../resources/build/icon.png   # generates src-tauri/icons/
npx tauri build                              # or: npx tauri dev
```

Linux build dependencies (Debian/Ubuntu): `libwebkit2gtk-4.1-dev`,
`libappindicator3-dev`, `librsvg2-dev`, `patchelf`.

## Changing the server

Edit `app.windows[0].url` in `src-tauri/tauri.conf.json`
(e.g. `https://orca.zcus6.zcus.dev` or `https://orca-rs.zcus.dev`).
