//! Standalone orca-daemon-rs binary: the Fase 3 Rust daemon as a
//! headless server (this is what runs on zcus6). The same crate is
//! linked into the Rust desktop app (app-rs), which runs it
//! in-process — one binary, one runtime, no Node.

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("ORCA_DAEMON_RS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6773);
    let daemon = orca_daemon_rs::start(orca_daemon_rs::DaemonConfig {
        profile_dir: None,
        port,
        web_root: None,
    })
    .await
    .expect("daemon failed to start");
    let _ = daemon.handle.await;
}
