//! The device registry: the profile's orca-devices.json, held as
//! raw rows so mutations (pairing offers, ticket exchange, device
//! key forks) persist without dropping fields this daemon does
//! not model. Mirrors upstream's device-registry semantics for
//! the operations daemon-rs implements.

use serde_json::{json, Value};
use std::path::PathBuf;

use crate::channel::Device;
use crate::e2ee::verify_device_proof;

const TICKET_EXCHANGE_WINDOW_MS: u64 = 10 * 60_000;
const MAX_FORKS_PER_TOKEN_ROW: usize = 32;

pub struct Registry {
    dir: PathBuf,
    rows: Vec<Value>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_id(bytes: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; bytes];
    if getrandom::fill(&mut buf).is_err() {
        return String::new();
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub(crate) fn uuid() -> String {
    let mut b = [0u8; 16];
    if getrandom::fill(&mut b).is_err() {
        return random_id(16);
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

impl Registry {
    pub fn load(dir: PathBuf) -> Registry {
        let rows = std::fs::read_to_string(dir.join("orca-devices.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        Registry { dir, rows }
    }

    pub fn count(&self) -> usize {
        self.rows.len()
    }

    pub fn devices(&self) -> Vec<Device> {
        self.rows
            .iter()
            .filter_map(|row| {
                Some(Device {
                    device_id: row.get("deviceId")?.as_str()?.to_string(),
                    token: row.get("token").and_then(|v| v.as_str()).map(str::to_string),
                    exchange_token: row
                        .get("exchangeToken")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    device_public_key_b64: row
                        .get("devicePublicKeyB64")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                })
            })
            .collect()
    }

    fn persist(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&Value::Array(self.rows.clone())) {
            let _ = std::fs::write(self.dir.join("orca-devices.json"), text);
        }
    }

    fn row_mut(&mut self, device_id: &str) -> Option<&mut Value> {
        self.rows
            .iter_mut()
            .find(|row| row.get("deviceId").and_then(|v| v.as_str()) == Some(device_id))
    }

    /// Mints this run's web pairing offer, the way orcad serve
    /// does: a fresh ticket device row (stale serve offers pruned)
    /// plus the offer for the web client URL fragment.
    pub fn mint_offer(&mut self, public_key_b64: &str, port: u16) -> Option<String> {
        use base64::Engine;
        let device_id = random_id(16);
        let device_token = random_id(32);
        if device_id.is_empty() || device_token.is_empty() {
            return None;
        }
        let now = now_ms();
        self.rows.retain(|row| {
            !(row.get("ticket").and_then(|v| v.as_bool()) == Some(true)
                && row.get("servesSessionBrowsers").and_then(|v| v.as_bool()) == Some(true))
        });
        self.rows.push(json!({
            "deviceId": device_id,
            "name": "Web pairing (daemon-rs)",
            "token": device_token,
            "scope": "runtime",
            "pairedAt": now,
            "lastSeenAt": now,
            "ticket": true,
            "servesSessionBrowsers": true,
        }));
        self.persist();
        let endpoint = std::env::var("ORCA_RS_ENDPOINT")
            .unwrap_or_else(|_| format!("ws://127.0.0.1:{port}/ws"));
        let offer = json!({
            "v": 2,
            "endpoint": endpoint,
            "deviceToken": device_token,
            "publicKeyB64": public_key_b64,
            "pairedDeviceId": device_id,
            "scope": "runtime",
        });
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&offer).unwrap_or_default());
        let web_base = std::env::var("ORCA_RS_WEB_URL")
            .unwrap_or_else(|_| format!("http://127.0.0.1:{port}/web-index.html"));
        Some(format!("{web_base}#pairing={code}"))
    }

    /// Records a successful sign-in: a ticket token's first
    /// sighting starts its exchange window; signing in with the
    /// exchange token retires the pairing ticket (single use).
    pub fn note_auth(&mut self, device_id: &str, presented_token: Option<&str>) {
        let Some(token) = presented_token else { return };
        let mut changed = false;
        if let Some(row) = self.row_mut(device_id) {
            let obj = row.as_object_mut().unwrap();
            if obj.get("exchangeToken").and_then(|v| v.as_str()) == Some(token) {
                obj.insert("token".to_string(), json!(token));
                obj.remove("exchangeToken");
                obj.remove("ticket");
                obj.remove("ticketFirstSeenAt");
                changed = true;
            } else if obj.get("ticket").and_then(|v| v.as_bool()) == Some(true)
                && obj.get("ticketFirstSeenAt").is_none()
            {
                obj.insert("ticketFirstSeenAt".to_string(), json!(now_ms()));
                changed = true;
            }
            obj.insert("lastSeenAt".to_string(), json!(now_ms()));
        }
        if changed {
            self.persist();
        }
    }

    /// pairing.exchangeTicket: the ticket's owner proposes its own
    /// replacement token; the pairing token keeps working until
    /// the replacement first signs in.
    pub fn exchange_ticket(
        &mut self,
        device_id: &str,
        presented_token: &str,
        new_token: &str,
    ) -> Result<String, String> {
        let now = now_ms();
        let row = self
            .rows
            .iter()
            .find(|row| row.get("deviceId").and_then(|v| v.as_str()) == Some(device_id))
            .ok_or("device_not_found")?;
        if row.get("parentDeviceId").is_some() {
            return Err("delegated_device".to_string());
        }
        if row.get("ticket").and_then(|v| v.as_bool()) != Some(true)
            || row.get("credentialKind").is_some()
            || row.get("token").and_then(|v| v.as_str()).is_none()
        {
            return Err("not_a_ticket".to_string());
        }
        if row.get("token").and_then(|v| v.as_str()) != Some(presented_token) {
            return Err("ticket_already_exchanged".to_string());
        }
        match row.get("exchangeToken").and_then(|v| v.as_str()) {
            Some(existing) if existing == new_token => return Ok(device_id.to_string()),
            Some(_) => return Err("ticket_exchange_pending".to_string()),
            None => {}
        }
        let first_seen = row.get("ticketFirstSeenAt").and_then(|v| v.as_u64());
        if first_seen.map(|seen| now.saturating_sub(seen) > TICKET_EXCHANGE_WINDOW_MS) != Some(false)
        {
            return Err("ticket_window_closed".to_string());
        }
        if self.rows.iter().any(|other| {
            other.get("deviceId").and_then(|v| v.as_str()) != Some(device_id)
                && (other.get("token").and_then(|v| v.as_str()) == Some(new_token)
                    || other.get("exchangeToken").and_then(|v| v.as_str()) == Some(new_token))
        }) {
            return Err("device_token_in_use".to_string());
        }
        if let Some(row) = self.row_mut(device_id) {
            row.as_object_mut()
                .unwrap()
                .insert("exchangeToken".to_string(), json!(new_token));
        }
        self.persist();
        Ok(device_id.to_string())
    }

    /// pairing.registerDeviceKey: forks the caller's token row
    /// into a device-key row after a 'register' proof over this
    /// connection's transcript hash.
    pub fn register_device_key(
        &mut self,
        caller_device_id: &str,
        public_key_b64: &str,
        proof_b64: &str,
        label: Option<&str>,
        ephemeral: bool,
        transcript_hash_b64: Option<&str>,
    ) -> Result<(String, u64), String> {
        let transcript = transcript_hash_b64.ok_or("device_key_requires_e2ee_v2")?;
        if !verify_device_proof(public_key_b64, proof_b64, "register", transcript) {
            return Err("bad_proof".to_string());
        }
        let legacy = self
            .rows
            .iter()
            .find(|row| row.get("deviceId").and_then(|v| v.as_str()) == Some(caller_device_id))
            .cloned()
            .ok_or("device_not_found")?;
        if legacy.get("credentialKind").and_then(|v| v.as_str()) == Some("device-key")
            || legacy.get("token").is_none()
        {
            return Err("device_already_keyed".to_string());
        }
        if legacy.get("parentDeviceId").is_some() {
            return Err("delegated_device".to_string());
        }
        let same_key: Vec<&Value> = self
            .rows
            .iter()
            .filter(|row| row.get("devicePublicKeyB64").and_then(|v| v.as_str()) == Some(public_key_b64))
            .collect();
        if let Some(existing) = same_key
            .iter()
            .find(|row| row.get("forkedFrom").and_then(|v| v.as_str()) == Some(caller_device_id))
        {
            let id = existing
                .get("deviceId")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let revision = existing
                .get("credentialRevision")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            return Ok((id, revision));
        }
        if !same_key.is_empty() {
            return Err("device_key_in_use".to_string());
        }
        let forks = self
            .rows
            .iter()
            .filter(|row| row.get("forkedFrom").and_then(|v| v.as_str()) == Some(caller_device_id))
            .count();
        if forks >= MAX_FORKS_PER_TOKEN_ROW {
            return Err("too_many_device_keys".to_string());
        }
        let fallback = legacy
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Device")
            .to_string();
        let name = sanitize_label(label, &fallback);
        let now = now_ms();
        let mut entry = json!({
            "deviceId": uuid(),
            "name": name,
            "scope": legacy.get("scope").cloned().unwrap_or(json!("runtime")),
            "credentialKind": "device-key",
            "devicePublicKeyB64": public_key_b64,
            "forkedFrom": caller_device_id,
            "pairedAt": now,
            "lastSeenAt": now,
        });
        if ephemeral {
            entry
                .as_object_mut()
                .unwrap()
                .insert("ephemeral".to_string(), json!(true));
        }
        if let Some(grants) = legacy.get("grants") {
            entry
                .as_object_mut()
                .unwrap()
                .insert("grants".to_string(), grants.clone());
        }
        let new_id = entry
            .get("deviceId")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        self.rows.push(entry);
        if ephemeral {
            if let Some(row) = self.row_mut(caller_device_id) {
                let obj = row.as_object_mut().unwrap();
                if obj.get("servesSessionBrowsers").and_then(|v| v.as_bool()) != Some(true) {
                    obj.insert("servesSessionBrowsers".to_string(), json!(true));
                }
            }
        }
        self.persist();
        Ok((new_id, 0))
    }
}

/// Upstream sanitizeDeviceLabel: strip control/format chars,
/// collapse whitespace, trim, cap at 64 chars, fall back when empty.
fn sanitize_label(value: Option<&str>, fallback: &str) -> String {
    let Some(value) = value else {
        return fallback.to_string();
    };
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{feff}'))
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let capped: String = collapsed.chars().take(64).collect();
    if capped.is_empty() {
        fallback.to_string()
    } else {
        capped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket_registry() -> (Registry, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("daemon-rs-reg-{}", random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let rows = vec![json!({
            "deviceId": "offer-1",
            "name": "Web pairing (daemon-rs)",
            "token": "pairing-token",
            "scope": "runtime",
            "pairedAt": 1,
            "lastSeenAt": 1,
            "ticket": true,
            "servesSessionBrowsers": true,
        })];
        std::fs::write(
            dir.join("orca-devices.json"),
            serde_json::to_string(&rows).unwrap(),
        )
        .unwrap();
        (Registry::load(dir.clone()), dir)
    }

    #[test]
    fn ticket_exchange_lifecycle() {
        let (mut registry, _dir) = ticket_registry();
        // Before first sign-in the window is closed (unknown first sighting).
        assert_eq!(
            registry.exchange_ticket("offer-1", "pairing-token", "a".repeat(48).as_str()),
            Err("ticket_window_closed".to_string())
        );
        registry.note_auth("offer-1", Some("pairing-token"));
        let new_token = "b".repeat(48);
        assert_eq!(
            registry.exchange_ticket("offer-1", "pairing-token", &new_token),
            Ok("offer-1".to_string())
        );
        // Idempotent resend, pending for a different proposal.
        assert!(registry.exchange_ticket("offer-1", "pairing-token", &new_token).is_ok());
        assert_eq!(
            registry.exchange_ticket("offer-1", "pairing-token", &"c".repeat(48)),
            Err("ticket_exchange_pending".to_string())
        );
        // Signing in with the replacement retires the ticket.
        registry.note_auth("offer-1", Some(&new_token));
        let devices = registry.devices();
        assert_eq!(devices[0].token.as_deref(), Some(new_token.as_str()));
        assert!(devices[0].exchange_token.is_none());
    }

    #[test]
    fn sanitize_label_rules() {
        assert_eq!(sanitize_label(Some("  My   Phone\t"), "fb"), "My Phone");
        assert_eq!(sanitize_label(Some("   "), "fb"), "fb");
        assert_eq!(sanitize_label(None, "fb"), "fb");
    }
}
