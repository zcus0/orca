//! Access to the profile state store:
//! `profiles/<id>/profile-state.db`, a SQLite document table
//! (`profile_state_documents`: domain -> JSON payload). That is
//! where orcad keeps the workspace catalog (repos, projects,
//! worktrees, settings). daemon-rs reads it and — since the
//! Fase 4 desktop shell became a writer — writes individual
//! domains back in upstream's exact format, so the store stays
//! orcad-compatible.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Parses the JSON payload stored under `domain`, or None when the
/// store or the domain is absent (a fresh profile has neither).
pub fn read_domain(profile_dir: &Path, domain: &str) -> Option<Value> {
    let db = find_state_db(profile_dir)?;
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let payload: String = conn
        .query_row(
            "SELECT payload FROM profile_state_documents WHERE domain = ?1",
            [domain],
            |row| row.get(0),
        )
        .ok()?;
    serde_json::from_str(&payload).ok()
}

/// Writes one domain document, mirroring upstream's writer
/// (profile-state-documents.ts): same table, domain_version 1,
/// content_hash = sha256 hex of the payload, and the store-wide
/// revision counter in profile_state_meta bumped by one. When
/// the profile has no state store yet, one is created at
/// profiles/<active|local-default>/profile-state.db. Returns
/// false on any I/O failure; persistence must never crash the
/// caller.
pub fn write_domain(profile_dir: &Path, domain: &str, value: &Value) -> bool {
    use sha2::Digest;
    let db = match find_state_db(profile_dir) {
        Some(db) => db,
        None => {
            let id = active_profile_id(profile_dir)
                .unwrap_or_else(|| "local-default".to_string());
            let dir = profile_dir.join("profiles").join(id);
            if std::fs::create_dir_all(&dir).is_err() {
                return false;
            }
            dir.join("profile-state.db")
        }
    };
    let conn = match rusqlite::Connection::open(&db) {
        Ok(conn) => conn,
        Err(_) => return false,
    };
    let setup = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS profile_state_meta (
            key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS profile_state_documents (
            domain TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL,
            domain_version INTEGER NOT NULL, revision INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, content_hash TEXT NOT NULL
        );",
    );
    if setup.is_err() {
        return false;
    }
    let revision: i64 = conn
        .query_row(
            "SELECT value FROM profile_state_meta WHERE key = 'revision'",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        + 1;
    let payload = value.to_string();
    let content_hash = format!("{:x}", sha2::Sha256::digest(payload.as_bytes()));
    let updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let upsert = conn.execute(
        "INSERT INTO profile_state_documents
            (domain, payload, domain_version, revision, updated_at, content_hash)
         VALUES (?1, ?2, 1, ?3, ?4, ?5)
         ON CONFLICT(domain) DO UPDATE SET
            payload = excluded.payload, revision = excluded.revision,
            updated_at = excluded.updated_at, content_hash = excluded.content_hash",
        rusqlite::params![domain, payload, revision, updated_at, content_hash],
    );
    if upsert.is_err() {
        return false;
    }
    conn.execute(
        "INSERT INTO profile_state_meta (key, value) VALUES ('revision', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [revision.to_string()],
    )
    .is_ok()
}

fn find_state_db(profile_dir: &Path) -> Option<PathBuf> {
    let direct = profile_dir.join("profile-state.db");
    if direct.is_file() {
        return Some(direct);
    }
    let profiles = profile_dir.join("profiles");
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(id) = active_profile_id(profile_dir) {
        candidates.push(profiles.join(id));
    }
    if let Ok(entries) = std::fs::read_dir(&profiles) {
        let mut dirs: Vec<PathBuf> =
            entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        dirs.sort();
        candidates.extend(dirs);
    }
    candidates.iter().map(|dir| dir.join("profile-state.db")).find(|db| db.is_file())
}

fn active_profile_id(profile_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(profile_dir.join("orca-profile-index.json")).ok()?;
    let index: Value = serde_json::from_str(&text).ok()?;
    for key in ["activeProfileId", "currentProfileId", "defaultProfileId"] {
        if let Some(id) = index.get(key).and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
    }
    None
}
