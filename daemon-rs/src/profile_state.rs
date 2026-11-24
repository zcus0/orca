//! Read-only access to the profile state store:
//! `profiles/<id>/profile-state.db`, a SQLite document table
//! (`profile_state_documents`: domain -> JSON payload). That is
//! where orcad keeps the workspace catalog (repos, projects,
//! worktrees, settings). daemon-rs reads it; it never writes —
//! the store stays orcad-compatible.

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
