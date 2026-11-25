# Fase 3 — Native Rust daemon (orcad rewrite)

Started 2026-11-24 at Zekus's direction ("coba rewrite ke rust juga").
Goal: replace the Node orcad runtime with a native Rust daemon so the
whole Orca RS stack (Tauri shell + daemon) is Rust — no bundled Node,
and a runtime that is actually lighter than orcad, not just a lighter
shell around the same runtime.

## What orcad actually is (mapped from fork source, 2026-11-24)

Three layers, not one program:

1. **Client-facing server** (what Orca RS's serve mode runs today):
   HTTP static web client + WebSocket endpoint. Transport security and
   pairing are E2EE: NaCl (tweetnacl) — pairing offer → device key proof
   (`src/shared/remote-runtime/pairing/device-key-proof.ts`,
   `remote-pairing-verification.ts`) → sealed-frame session
   (`remote-runtime-sealed-frame.ts`, `remote-runtime-client-framing.ts`,
   handshake in `remote-runtime-client-handshake.ts`). RPC is a custom
   envelope (`src/shared/remote-runtime/rpc/runtime-rpc-envelope.ts`)
   gated by RUNTIME_PROTOCOL_VERSION.
2. **Terminal daemon**: a SEPARATE process orcad spawns, speaking over a
   unix socket in the profile dir (`daemon/daemon-v62.sock`) — the "v62"
   protocol. PTYs live there, not in the server process.
3. **Profile store**: the profile dir holds JSON state —
   `host-installation.json` (installation identity), `orca-devices.json`
   (paired devices), `orca-e2ee-keypair.json` (host NaCl keypair),
   `orca-profile-index.json`, `orca-runtime.json`,
   `orca-secret-protection.json`, `profiles/` (per-profile state incl.
   sqlite), plus `orcad.lock` (the instance lock 0.2.2 relies on).

The web client's RPC surface (session graph, hosts, terminals, agent
sessions, files) is the long tail: `src/shared/remote-runtime/` alone
has ~35 modules. Full parity is months. We go subset-first, in the
order the client exercises things: boot → pairing → status → sessions.

## Milestones

- **M1 — Identity + transport skeleton.** daemon-rs reads the ORIGINAL
  profile (same dir as 0.2.2 uses), loads installation identity +
  devices + keypair, serves the web statics, accepts the WS endpoint.
  Acceptance: starts against a real profile copy, reports the same
  installation id as orcad does.
- **M2 — Pairing compatibility.** Implement the pairing verification +
  E2EE sealed-frame session bit-compatibly (NaCl secretbox framing,
  counters, direction bytes). Acceptance: the real web client pairs
  with daemon-rs and stays connected; orcad and daemon-rs accept the
  same paired device from the same profile.
- **M3 — Status + session graph reads.** Runtime status, environment /
  host listing, session graph snapshots from profile state.
  Acceptance: the paired web client renders the workspace home with
  real data from the profile.
- **M4 — Terminals.** Implement the daemon-v62 socket protocol (or a
  Rust PTY host speaking it) so terminal panes work. Acceptance:
  open a terminal in the web client, run commands, resize, reconnect.
- **M5 — Agent sessions.** Spawn/supervise agent CLIs (claude/codex)
  with the session semantics the client expects (stream, resume,
  permissions). Acceptance: run a real coding session end-to-end.

Out of scope until M5 lands: relay/account cloud features, ephemeral
VM recipes, WSL hosts, SSH-host management (the client can still pair
to zcus6's real orcad for those).

## M2 protocol notes (from source, 2026-11-24)

Verified in `src/shared/remote-runtime/`:

- **Device proof** (`pairing/device-key-proof.ts`): Ed25519
  (nacl.sign.detached) over `"orca-device-proof/v1\0<purpose>\0" ||
  transcriptHash[32]`, purpose ∈ `auth | redeem | register`. Device
  public key 32 B, signature 64 B, canonical base64 only. Devices in
  `orca-devices.json` are verified against their registered key.
- **Sealed frames** (`remote-runtime-sealed-frame.ts`): after the
  handshake, frames go through a channel (`openText` / `openBinary`);
  the E2EE "ready" verdict is always a PLAIN TEXT frame. Framing has a
  legacy mode and **v2**; v2 binary frames may carry compressed text
  (`e2ee/paired-e2ee-compressed-frame.ts`, node codec in
  `e2ee/node/paired-e2ee-node-compressed-frame.ts`).
- **Mobile v2 framing** (`e2ee/mobile-e2ee-v2-framing.ts`): NaCl
  secretbox; frame = nonce[24] || secretbox(header || payload) where
  header = sessionId[32] || direction[1] || kind[1] || counter[8 BE],
  frame version 2, nonce derived from the same header fields.
- **Key schedule / session**: `e2ee/paired-e2ee-v2-key-schedule.ts`,
  `e2ee/paired-e2ee-v2-client-session.ts`, primitives in
  `e2ee/paired-e2ee-primitives.ts` (+ node variants in `e2ee/node/`).
  Client handshake sequence: `e2ee/paired-e2ee-client-handshake.ts`
  (states awaiting_ready → awaiting_authenticated → ready; token auth
  frame `{kind:'token', deviceToken}` also exists for serve).
- **RPC envelope**: `rpc/runtime-rpc-envelope.ts` (RuntimeRpcRequest /
  RuntimeRpcResponse) — read before M3.

Rust crypto equivalents: `ed25519-dalek` (proof verify), `crypto_box`
/ `crypto_secretbox` via `xsalsa20poly1305` (tweetnacl-compatible),
BLAKE2b/SHA-512 per the key schedule file. The pairing offer format
and the server-side accept path (in the orcad serve entry) still need
a read-through before coding M2.

- **V2 key schedule** (`e2ee/paired-e2ee-v2-key-schedule.ts`, complete):
  transcriptHash = SHA256(transcript);
  salt = SHA256("orca-mobile-e2ee/v2/salt\0" || clientNonce[32] ||
  desktopNonce[32]); info = "orca-mobile-e2ee/v2/session\0" ||
  transcriptHash; expanded = HKDF-SHA256(sharedSecret[32], salt,
  info, 96) → client→host key [0:32], host→client key [32:64],
  sessionId [64:96]. Rust: `hkdf` + `sha2` crates, direct port.
- **Auth after ready** (`e2ee/paired-e2ee-client-handshake.ts`): the
  client sends `{type:'e2ee_auth', v:2, transcriptHashB64, ...}` —
  either a deviceToken, or an Ed25519 device proof over
  `encodeDeviceProofMessage('auth', transcriptHash)`. The host's
  authenticated reply must echo the session's transcriptHashB64 with
  exactly the keys `{transcriptHashB64, type, v}`.
- **Shared secret**: curve25519 DH via primitives.deriveSharedKey
  (host keypair from `orca-e2ee-keypair.json` × device public key).
- **Hello/ready** (`e2ee/mobile-e2ee-v2-contract.ts`, complete):
  client → `{type:'e2ee_hello', v:2, clientPublicKeyB64,
  clientNonceB64, capabilities:{framing:[2], payloadKinds:['text',
  'binary']}, context}` with an EPHEMERAL client keypair; host →
  `{type:'e2ee_ready', v:2, desktopPublicKeyB64, clientNonceB64
  (echo), desktopNonceB64, selection:{framing:2, payloadKinds:
  ['text','binary']}, context}`. Both records are exact-key
  validated; contexts must be identical (protocol 'orca-mobile-e2ee',
  initiator 'mobile', responder 'desktop', transport 'direct' |
  'relay'). The client pins the desktop public key from the pairing
  offer and rejects a re-keyed host.
- **Transcript** (same file, complete): fixed-order labeled fields,
  each `uint32BE(name_len) || name || uint32BE(value_len) || value`,
  starting with domain 'orca-mobile-e2ee/v2/transcript', then all
  hello fields under 'mobile-to-desktop._', then ready fields under
  'desktop-to-mobile._' (incl. client-nonce echo). Number lists:
  uint32BE(count) || uint32BE(each); string lists: uint32BE(count) ||
  (uint32BE(len) || utf8) each. uint32 is big-endian throughout.
  Remaining read before coding the WS handler: the serve entry's
  pairing-offer format + WS endpoint path + host-side e2ee_auth
  handling. Host-side session implementation to mirror:
  `src/main/runtime/rpc/mobile/e2ee/mobile-e2ee-v2-desktop-session.ts`
  (+ `e2ee-channel.ts` in the same dir).

## M2 progress

- 2026-11-24: transcript encoding + v2 key schedule implemented in
  `daemon-rs/src/e2ee.rs` and **verified bit-compatible against
  upstream's own test vector** (`mobile-e2ee-v2-fixtures.ts`):
  transcript length 1347, transcriptHash ca6385f8…, both session keys
  and the sessionId all match exactly (`cargo test` green).
  Next: secretbox frame seal/open (mobile-e2ee-v2-framing port), the
  WS hello→ready handler mirroring
  `src/main/runtime/rpc/mobile/e2ee/mobile-e2ee-v2-desktop-session.ts`,
  and device-proof verification (ed25519).
- 2026-11-24 (later): sealed-frame layer ported (`seal_frame` /
  `open_frame` in the same module, XSalsa20-Poly1305 via the
  `xsalsa20poly1305` crate). All upstream framing test cases pass:
  the counter-0 nonce layout matches upstream's expected hex exactly,
  round-trip works, and replay/gap/reflection/kind-confusion/
  cross-session frames are all rejected.
- 2026-11-24 (later still): the rest of the M2 crypto core is done
  and verified — 6/6 tests green. X25519 DH with NaCl's HSalsa20
  post-processing (hand-written HSalsa20 core; `nacl.box.before`
  reproduced exactly against a tweetnacl-computed vector), Ed25519
  device-proof verification (tweetnacl signature vector; wrong
  purpose / wrong transcript hash rejected), and `DesktopSession`
  (hello validation → ready → bidirectional sealed text with
  counters; full client↔desktop loop test passes, wrong-transport
  hello refused). Remaining in M2: wire DesktopSession into
  daemon-rs's WS handler (hello frame → ready frame → e2ee_auth →
  authenticated reply), read the serve entry for the WS path and
  post-auth flow, then the end-to-end test against the real web
  client.
- 2026-11-24 (evening): WS channel WIRED and E2E-verified over a
  real socket. `daemon-rs/src/channel.rs` ports E2EEChannel's v2
  path (hello → ready → sealed auth → sealed e2ee_authenticated →
  RPC passthrough; 10 s handshake deadline → 4002; decrypt failure
  in auth → 4001 Unauthorized; 5 consecutive failures → 4003;
  auth failures get the sealed e2ee_error + mapped close reason).
  Auth classification ported: token shape and device-key proof
  shape against the profile's orca-devices.json. 9/9 unit tests
  green (token flow, wrong-token sealed error, device-key flow,
  plus the 6 crypto tests). E2E: an independent Node client
  (tweetnacl + node HKDF, written from the spec) paired with the
  real daemon binary over ws://127.0.0.1:6773/ws — both sides
  derived identical keys, the daemon authenticated the device and
  the client verified the sealed e2ee_authenticated transcript
  hash (E2E_OK). Remaining in M2: the FIRST-pair offer flow (new
  device registration from the pairing URL — the E2E above covers
  already-paired reconnect auth) and a real browser web-client
  run.
- 2026-11-24 (evening, later): FIRST-pair flow done. daemon-rs
  mints a per-start pairing offer like orcad serve: a fresh ticket
  device row (scope runtime, servesSessionBrowsers) persisted to
  the profile's orca-devices.json (stale serve offers pruned), and
  the PairingOffer {v:2, endpoint, deviceToken, publicKeyB64,
  pairedDeviceId, scope} base64url-encoded into the printed
  web-index.html#pairing= URL (ORCA_RS_ENDPOINT / ORCA_RS_WEB_URL
  override for proxied deploys). Verified E2E from an empty
  registry: a client starting from ONLY the URL decoded the
  offer, pinned the host key from it, authenticated with the
  offer token — E2E_OK. M2 protocol work is COMPLETE; the only
  remaining acceptance item is the literal real-browser run,
  which needs daemon-rs deployed somewhere a browser can reach
  (zcus6 test vhost, like Fase 1's serve-rs test).

## Separate identity (2026-11-24 16:40, user's words)

Orca RS must be a DIFFERENT runtime from normal Orca so both can
be open at the same time. This supersedes 0.2.2's shared-profile
approach (which made them mutually exclusive via orcad's instance
lock — the exact thing he now rejects). Design:

- RS profile dir is its own: `orca-rs` beside the original's
  `orca` (e.g. %APPDATA%\orca-rs). Own installation id, host
  keypair, device registry, runtime lock, daemon socket, ports.
- First run imports a COPY of the original profile (identity
  files, devices, settings, profiles/) so his accounts,
  environments, bot team and projects come along — excluding
  live runtime state (daemon/, orcad.lock, orca-runtime.json).
  After the import the two profiles evolve independently.
- Consequence he accepts by asking for this: RS is a separate
  host to pair with (its own pairing URL); the original's
  pairings are untouched, and vice versa.

## M3 progress log

- 2026-11-24 (evening): slice 1 done — the RPC layer itself.
  Wire format (from fork source): request {id, deviceToken,
  method, params, ...orchestration fields}; response envelope
  {id, ok, result|error{code,message}, _meta:{runtimeId}};
  keepalive frames {_keepalive:true} take no reply; unknown
  methods get error code method_not_found ("Unknown method: X"),
  matching upstream's admission prologue. daemon-rs src/rpc.rs
  implements the bootstrap surface: host.platform →
  {platform}, host.peerDesktops → {peers:[]},
  runtime.clientCapabilities.update, runtime.clientEvents
  .subscribe/unsubscribe, session.tabs.listAll + subscribeAll →
  {snapshots:[]} (SessionTabsInventory shape; empty until
  M4/M5), session.tabs.unsubscribeAll. Every request's
  deviceToken is checked against the socket's authenticated
  token (mismatch → unauthorized envelope). Per-run runtimeId
  minted at startup. 12/12 cargo tests green; verified E2E over
  a real socket: first-pair auth → host.platform, listAll and a
  bogus method all answered with correctly sealed envelopes.
  Next M3 slices: workspace/project data the client's home
  screen reads (profile store under profiles/), then the
  pairing.exchangeTicket + registerDeviceKey RPCs the web
  client calls after first auth.
- 2026-11-24 (evening): slice 2 done — status.get + the pairing
  writes. The device registry moved into src/registry.rs (raw
  rows, persisted on mutation; channel snapshots derive from
  it). status.get: probe → {runtimeId}; full → the RuntimeStatus
  shape (graphStatus 'ready', protocol 3, min client 2,
  hostPlatform, machineName, appVersion, pairedDeviceId) with an
  HONEST capability list (only what is implemented:
  pairing.device-key.v1, pairing.device-key-ephemeral.v1,
  pairing.e2ee-v2-token-capabilities.v1,
  pairing.ticket-exchange.v1). pairing.exchangeTicket follows
  upstream's planTicketExchange exactly (ticket-only, presented
  token must be the pairing token, idempotent resend, pending
  conflict, 10-minute window from ticketFirstSeenAt,
  device_token_in_use); sign-in records ticketFirstSeenAt, and
  signing in with the exchange token retires the ticket
  (channel accepts token OR exchangeToken; note_auth performs
  the retirement). pairing.registerDeviceKey implements
  planDeviceKeyFork (proof purpose 'register' over the socket's
  transcript hash, forkedFrom row with credentialKind
  'device-key', idempotent same-key fork, 32-fork cap,
  ephemeral forks mark the legacy row servesSessionBrowsers).
  15/15 cargo tests green. E2E over real sockets for the full
  exchange lifecycle: pair → status → exchange → reconnect with
  the new token (registry shows the ticket retired) → old
  pairing token refused.
- 2026-11-24 (evening): registerDeviceKey E2E done over a real
  socket: ticket sign-in → register an ephemeral key (proof
  purpose 'register' over the live transcript) → forked row
  persisted exactly like upstream's plan (UUID id,
  credentialKind 'device-key', forkedFrom the offer row,
  ephemeral) → a mismatched proof refused with bad_proof →
  reconnect with device-key auth (purpose 'auth') and a working
  status probe.
- 2026-11-24 (evening): workspace-read scoping. repo.list →
  {repos: Repo[], repoIconIds} (Repo core: id, path, displayName,
  badgeColor, addedAt, kind git|folder + many optional fields).
  The data lives in the profile store: profiles/<profileId>/
  profile-state.db — a SQLite database (verified on the real
  serve-2 profile on zcus6: profile id 'local-default', db + wal
  - rotating backups + .authority file). Next step: read the
    schema (read-only) to find the repos document, then implement
    repo.list (+ project.list / worktree reads as the client
    needs) in daemon-rs with a SQLite reader (rusqlite bundled).

## Test deployment (2026-11-24 17:01, at his "mana hasilnya")

daemon-rs is LIVE on zcus6 as a public test: unit
orca-daemon-rs.service (User=orca, port 127.0.0.1:6774, own
profile ~/orca-daemon-rs/profile, web root borrowed from
~/orca-serve-rs/web), nginx vhost orca-rsd.zcus.dev (Basic-auth
like the other Orca vhosts, wildcard cert), explicit Cloudflare
A orca-rsd → 129.225.6.123 proxied. Public check: 401 (auth
gate answering). First-run identity generation was added for
this (fresh profile mints installation id + host keypair,
0600). Pairing URL is printed in `journalctl -u orca-daemon-rs`
per start. This is also the long-pending M2 real-browser
acceptance target. Cleanup when the test ends: disable the
unit, remove the vhost + Cloudflare record + ~/orca-daemon-rs.

## Direction freeze (2026-11-24 16:37, user's words)

0.2.2 still spawns node.exe → orcad as a child process, and the
user rejected that as the end state: the Windows desktop exe must
BE the runtime — one binary, one process, not an app fronting a
separate server. Consequences:

- The spawn-orcad release line is FROZEN at 0.2.2. No 0.2.3.
- The next release is the single-process build: daemon-rs linked
  INTO the Tauri app (same binary, in-process), zero Node.
- All effort goes to Fase 3 milestones until daemon-rs covers the
  client's core RPC surface (M2 pairing → M3 status/sessions →
  M4 terminals).

## Ground rules

- Bit-compatibility is the contract: same profile dir, same pairing
  crypto, same envelope. Anything less forks the user's data.
- orcad stays the fallback at every milestone — daemon-rs ships as an
  opt-in binary until a milestone's acceptance test passes against the
  real web client.
- No changes to the profile format. Read-only until M3.

## Release lines (2026-11-24, his call)

Two separate lines, separate branches and tag prefixes — never a bare `v*` tag again:

- **Tauri line** — branch `tauri`, tags `tauri-v*` (next: `tauri-v0.2.3`).
  Shell swap ONLY: Electron replaced by Tauri, everything else stays
  upstream — the runtime is still the original Node orcad, bundled and
  spawned. Workflow `orca-rs-release.yml` builds the desktop installers
  - serve-rs. The old bare tags `v0.2.1` / `v0.2.2` are this line's
    history.
- **Rust line** — branch `rust`, tags `rust-v*` (first: `rust-v0.1.0`).
  The full Rust rewrite: runtime AND application in Rust. Starts as the
  standalone `orca-daemon-rs` binary (workflow
  `orca-daemon-rs-release.yml`: linux x86_64/aarch64, windows x86_64,
  macos aarch64) and grows into the single-process Rust desktop app —
  daemon embedded in the app process, zero Node — still released under
  `rust-v*`. The integrated app does NOT ship on the Tauri line. Fase 3
  milestone work (M3 onward) lands on this branch.
- `main` stays the integration branch both lines fork from.

## M4 scoping (2026-11-25, from fork source)

The v62 terminal-daemon protocol lives in `src/main/daemon/protocol/`
(16 files, ~950 lines; `PROTOCOL_VERSION = 62` in
daemon-protocol-version.ts). Wire surface to mirror:

- Handshake: daemon-hello-protocol.ts (33 lines).
- Requests (daemon-rpc-contract.ts): createOrAttach,
  cancelCreateOrAttach, write, resize, pausePty, resumePty,
  setSessionBackground, kill, signal, listSessions, shutdownIfIdle,
  detach, getCwd, clearScrollback, resetInputModes,
  reportFocusLost, requestRepaint, shutdown, getSnapshot, getSize,
  takePendingOutput.
- Stream events (daemon-stream-events.ts): output / resize / clear
  with per-session output sequence numbers (v57: sequence starts at
  first attach).
- Snapshots/history replay: terminal-snapshot.ts,
  daemon-history-replay-pty.ts, daemon-checkpoint-file.ts.

Architecture note: upstream splits runtime <-> terminal daemon over
a unix socket (`daemon/daemon-v62.sock`) because the Electron main
process must not own PTYs. daemon-rs has no such constraint — the
PTY layer can live in-process (portable-pty) behind the same
semantics: hello/version gating, create-or-attach with snapshot
replay, sequenced output streaming. The client-facing side is the
session/tab RPC graph the web client already speaks to the runtime;
M4 wires those methods to real PTYs instead of the M3 empty
inventory. Version-gated behaviours that matter for a fresh daemon:
v60 requestRepaint, v57 sequence-at-first-attach, v51 fenced
termination, v31 stable pane attach-only.

## M4 map (2026-11-25, from fork source)

Client-facing terminal RPC lives in `src/main/runtime/rpc/methods/
terminal/` (~50 methods). The core loop the web client needs:
`terminal.create`, `terminal.send`, `terminal.read`,
`terminal.list`, `terminal.close`, `terminal.resizeForClient`,
`terminal.subscribe` / `terminal.multiplex` — output streams back
as BINARY frames over the sealed channel (the multiplex protocol:
terminal-multiplex-*.ts, ~20 files: frame delivery, flow control /
ack windows, initial snapshot, resume ledger). In daemon-rs those
binary frames are the `Action::RpcBinary` path in channel.rs,
currently logged and dropped.

Daemon-side (v62) semantics to mirror are in the contract above;
upstream splits runtime <-> PTY daemon only because Electron main
must not own PTYs. daemon-rs keeps PTYs in-process
(`src/pty.rs`, portable-pty). Socket-path doctrine
(src/main/daemon/AGENTS.md): daemon-rs never publishes or touches
orcad's canonical `daemon/daemon-v62.sock` path — non-interference
by design, so a Rust daemon and orcad can coexist on one profile
host without endpoint fights.

M4 slices:

1. PTY core (pty.rs): spawn/write/resize/kill, output ring buffer
   with sequence numbers, exit tracking. DONE 2026-11-25 (unit-
   tested against a real shell).
2. JSON RPC wiring: terminal.create/send/read/list/close with
   the client shapes from terminal-unary-params.ts (handle-based;
   send = {text, enter, interrupt} -> {accepted, bytesWritten};
   read pages the output stream by cursor). DONE 2026-11-25 —
   worktree selectors (`id:<uuid>`, bare id, or path) resolve to
   the repo path via the profile catalog; the Terminal object
   carries the graph-free fields (handle, ptyId, cwd, title,
   state, createdAt, cols/rows). RPC-level round-trip test drives
   a real shell (create -> send echo -> read marker -> list ->
   close). 19/19 tests green.
3. Streaming: terminal.subscribe + the multiplex binary protocol
   (snapshot on attach, sequenced live frames, ack/flow control,
   resume) — the bit-compat-heavy part.

## M4 slice 3 scoping (2026-11-25, from fork source)

Terminal output reaches the web client ONLY through the binary
multiplex protocol — there is no text-frame event channel for
terminal streams. Server-side `terminal.subscribe`
(terminal-subscribe-method.ts) is a streaming method whose emit()
events are encoded as binary frames
(`encodeTerminalStreamJson({kind: ...})`, fixtures in
src/renderer/src/components/terminal-pane/pty-transport/remote/
remote-runtime-pty-transport-stream-fixtures.ts) and routed by
runtime-binary-message-router.ts. The 'JSON subscription'
(terminal-subscribe-json-and-lease.ts) is JSON _payloads inside
those binary frames_, not WS text frames. Mobile clients REQUIRE
the binary stream (`binary_terminal_stream_required`).

Event kinds on a subscription: `subscribed` {streamId, lines,
truncated} (lease path), then for data subscriptions a
`scrollback` {lines (read tail), truncated, serialized, oscLinks,
cwd, cols, rows, displayMode, seq}, then `data` {chunk} batches,
and `fit-override-changed` {mode, cols, rows}. Params:
TerminalSubscribe = handle + optional client {id, type},
viewport, capabilities {terminalBinaryStream: 1, outputAck: 1,
...}, resume {streamToken, units}.

daemon-rs work for slice 3, in order:

1. WS loop refactor: split sink/stream + an outbound queue so the
   daemon can push sealed frames outside request/response
   (channel.rs Action::RpcBinary stops being a dead end).
2. Multiplex frame codec per the fixtures + stream-schemas.ts
   (frame header, stream ids, snapshot/data/ack kinds).
3. terminal.subscribe/unsubscribe over the PTY core: scrollback
   from the ring buffer (raw bytes split to lines — daemon-rs has
   no terminal emulator, so `serialized` stays absent), data
   events from the pump, ack/flow-control window.
4. Session graph bridge: terminals created via terminal.create
   must appear in session.tabs snapshots for the web client to
   render panes at all (overlaps M3's remaining graph work).

## M4 progress

- 2026-11-25: slice 3a done — the multiplex frame codec
  (src/stream.rs), byte-exact against terminal-stream-protocol.ts
  with golden-vector tests. 22/22 cargo tests green.
- 2026-11-25: slice 3b step 1 done — the WS loop refactor
  (scoping item 1 above). handle_ws now splits the socket, runs
  a writer task draining an mpsc queue, and shares the E2EE
  channel behind a mutex; the `Outbound` handle lets background
  producers seal binary frames (new `Channel::seal_binary`,
  over the existing DesktopSession::seal_binary) and push them
  outside request/response. Handshake deadline, auth actions and
  RPC replies all funnel through the queue. Verified: cargo
  build clean, 22/22 tests green, live smoke — a raw WS client
  completed the v2 hello → ready exchange against the rebuilt
  binary. Next in 3b: terminal.multiplex as a streaming method
  (emit {type:'ready'}, binary control handler on streamId 0)
  - Subscribe/Input/Resize/Unsubscribe frame handling (step 3),
    then the session-graph bridge (step 4).
- 2026-11-25: slice 3b step 2 done — the multiplex itself
  (new src/multiplex.rs). `terminal.multiplex` answers the
  standard envelope with result {type:'ready'} (the streaming
  method's first emit, per the client transport fixtures);
  binary frames then route per connection: Subscribe on
  streamId 0 (payload names streamId + terminal; viewport
  resizes first) → SnapshotStart {kind:'scrollback'} /
  SnapshotChunk (≤64 KiB) / SnapshotEnd from the ring buffer,
  then a 40 ms pump task streams Output frames with per-stream
  sequence numbers; Input writes to the PTY, Resize /
  ClaimViewport resize it, Unsubscribe aborts the pump,
  SnapshotRequest re-sends the snapshot, Ack / SetOutputPaused
  / SetOutputCadence are accepted and ignored. Subset limits:
  no outputAck credit-window enforcement, no resume ledger,
  no viewport-claim arbitration. Verified E2E against the live
  binary with an independent Node client (tweetnacl +
  node hkdfSync, transcript mirrored from e2ee.rs): pair →
  terminal.create → multiplex ready → snapshot opcodes 2,3,4 →
  Input 'echo mux-marker' → Output frame carrying the marker
  (MUX_E2E_OK). Remaining in 3b: the session-graph bridge
  (step 4) so panes render from session.tabs snapshots.
- 2026-11-25: slice 3b step 4 done — the session-graph bridge
  (new src/graph.rs). Flat honest subset: one group per
  worktree, terminal tabs only, each tab a single leaf whose
  `terminal` is the PTY handle. `session.tabs.createTerminal`
  spawns a PTY (shared spawn path with terminal.create) and
  publishes a RuntimeMobileSessionTerminalClientTab
  {type:'terminal', status:'ready', terminal, ptyId, leafId,
  parentTabId, isActive} inside a RuntimeMobileSessionTabsResult
  snapshot (publicationEpoch minted per worktree,
  snapshotVersion bumps per mutation, tabGroups with tabOrder);
  `session.tabs.list` / `listAll` serve the same snapshots,
  `subscribe` answers {type:'snapshot', ...} and
  `subscribeAll` the inventory (streaming emits approximated
  by the current snapshot — no live push of graph changes
  yet), `session.tabs.close` retires tab + PTY, and
  status.get now reports real liveTabCount/liveLeafCount.
  The graph lives in AppState, shared across connections.
  Worktree key = resolved repo path when the selector names a
  catalog repo, else the selector verbatim. Verified: 23/23
  cargo tests (new graph cycle test) + live E2E — pair →
  createTerminal → snapshot carries one ready tab →
  listAll contains it → multiplex subscribes to its handle →
  snapshot frames + echo Output (GRAPH_MUX_E2E_OK).
  M4's remaining acceptance is the real web client run
  against the zcus6 test deploy (daemon-rs there still runs
  the M3 build — redeploy before browser testing).

## M5 scoping (2026-11-25, from fork source)

Two distinct agent surfaces exist upstream:

1. **TUI agent sessions** — `terminal.createAgentSession` /
   `terminal.ensureAgentSession`
   (src/main/runtime/rpc/methods/terminal/agent-session.ts;
   params in src/shared/rpc-contract/terminal/agent-session-params.ts).
   The agent CLI (TuiAgent catalog, ~37 ids in
   src/shared/agent-launch/catalog/tui-agent.ts) runs as a TUI
   inside a PTY; in the session graph it is a TERMINAL tab with
   `launchAgent` set (RuntimeMobileSessionTerminalTab). Create
   result: {terminal: RuntimeTerminalCreate, disposition:
   'created' | 'replayed'} with idempotency keyed on
   clientOperationId. Prompt delivery is typed into the TUI
   ('auto-submit' appends Enter; 'draft' does not). Resume
   (ensure, kind 'explicit') uses per-agent argv from
   agent-resume-argv.ts: claude --resume <id>, codex resume
   <id>, opencode --session <id>, pi --session <transcript>,
   omp ... --resume <target>.
2. **Structured chat sessions** — the `agentSession.*` namespace
   (create/cancel/approve/commands/conversation/...): a hosted
   provider-protocol layer, much larger. OUT of M5's first
   slices; the TUI path is what Orca's panes use for CLI agents.

daemon-rs M5 slice 1 = the TUI path: agent catalog (id →
executable) for the common agents, createAgentSession on the
shared PTY spawn + graph publish (tab carries launchAgent),
typed prompt delivery, ensureAgentSession explicit resume for
claude/codex/opencode/pi/omp. Deliberate subset limits: no
launch accounts/env routing, no spawn-intent deferral, no
agent status inference (tabs carry no agentStatus), automatic
ensure (sleeping checkpoints) refused.
- 2026-11-25: M5 slice 1 done — the TUI agent path
  (src/agents.rs + rpc/graph wiring). Catalog maps the common
  TuiAgent ids to their CLI executables (~24 agents).
  `terminal.createAgentSession` validates the agent, honors
  clientOperationId idempotency (same op id → the original
  terminal with disposition 'replayed'), spawns via the shared
  PTY path with agentArgs/extraAgentArgs appended raw,
  publishes a graph tab carrying `launchAgent`, and types the
  prompt into the TUI after 1.2 s (Enter appended unless
  promptDelivery 'draft'). `terminal.ensureAgentSession`
  implements kind 'explicit' resume for claude/codex/opencode/
  opencode2/pi/omp with upstream's argv; kind 'automatic' is
  refused (no sleeping-checkpoint store). Versions bumped to
  0.3.1 (daemon crate, app crate, tauri.conf) so release asset
  names match the tag. Verified: 25/25 cargo tests + live E2E
  (create → replay → graph launchAgent → ensure resume →
  unknown agent refused; M5_E2E_OK). Still open in M5: the
  structured `agentSession.*` chat host, agent status
  inference, launch accounts/env.
