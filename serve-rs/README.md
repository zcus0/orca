# orca-serve-rs

A small Rust supervisor + transparent HTTP/WebSocket front for Orca's
headless runtime (`orcad.js serve` mode). It spawns orcad on an ephemeral
port, reads its JSON readiness line, and proxies HTTP and WebSocket traffic
to it untouched — the E2EE pairing handshake stays bit-compatible because
payloads are never parsed or modified.

```sh
cargo build --release
./target/release/orca-serve-rs \
  --port 6772 --bind 127.0.0.1 \
  --orcad-entry /path/to/orcad.js \
  --web-dir /path/to/out/web \
  --data-dir /path/to/data \
  --pairing-address wss://your-host.example
```

`GET /healthz` reports the child state. The pairing URL is printed once to
stdout at startup. Prebuilt Linux binaries (x86_64 and aarch64) are attached
to this repository's GitHub Releases by CI.
