//! Live proof for the shell-swap client: spawns a real orcad
//! serve on a scratch profile, pairs with the Rust E2EE
//! client, and calls status.get + repo.list.
//! Usage: orca-client-test <node> <orcad.js> <web-root> <data-dir>

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use orca_daemon_rs::client::{parse_offer, RuntimeClient};

fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let standard = value.replace('-', "+").replace('_', "/");
    let padded = match standard.len() % 4 {
        0 => standard,
        n => format!("{standard}{}", "=".repeat(4 - n)),
    };
    base64::engine::general_purpose::STANDARD.decode(padded).ok()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (node, orcad, web_root, data_dir) = (&args[1], &args[2], &args[3], &args[4]);
    std::fs::create_dir_all(data_dir).expect("data dir");
    let mut child = Command::new(node)
        .arg(orcad)
        .args(["--port", "0", "--bind", "127.0.0.1", "--json"])
        .arg("--web-client-root")
        .arg(web_root)
        .env("ORCA_USER_DATA", data_dir)
        .env("ORCA_USER_DATA_PATH", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn orcad");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut offer = None;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).expect("read readiness");
        if read == 0 {
            break;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if value.get("type").and_then(|t| t.as_str()) == Some("orca_server_ready") {
            let url = value
                .get("pairing")
                .and_then(|p| p.get("webClientUrl"))
                .and_then(|u| u.as_str())
                .expect("webClientUrl")
                .to_string();
            let blob = url.split("#pairing=").nth(1).expect("pairing fragment");
            let decoded_url = urlencoding_decode(blob);
            let code = decoded_url
                .split("?code=")
                .nth(1)
                .expect("pair code parameter");
            let decoded = b64url_decode(code).expect("offer b64");
            let offer_json: serde_json::Value =
                serde_json::from_slice(&decoded).expect("offer json");
            println!("offer endpoint: {}", offer_json["endpoint"]);
            offer = parse_offer(&offer_json);
            break;
        }
    }
    let offer = offer.expect("pairing offer");
    let mut client = RuntimeClient::connect(&offer).await.expect("client connect");
    println!("E2EE handshake + token auth: OK");
    let status = client
        .call("status.get", serde_json::json!({}))
        .await
        .expect("status.get");
    println!("status.get ok={} runtime={}", status["ok"], status["result"]["runtimeId"]);
    let repos = client
        .call("repo.list", serde_json::json!({}))
        .await
        .expect("repo.list");
    println!("repo.list ok={} count={}", repos["ok"], repos["result"]["repos"].as_array().map_or(0, Vec::len));
    println!("CLIENT_E2E_OK");
    let _ = child.kill();
}

fn urlencoding_decode(value: &str) -> String {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
