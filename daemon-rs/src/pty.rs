//! PTY core (Fase 3 M4, slice 1): real terminal sessions owned
//! in-process by daemon-rs — spawn, input, resize, kill, and an
//! output ring buffer with per-session sequence numbers (the
//! v62 daemon starts a session's output sequence at its first
//! attach; here the buffer is the attach snapshot source).
//!
//! Upstream splits this into a separate daemon process because
//! the Electron main process must not own PTYs; daemon-rs has no
//! such constraint, so the PTY layer lives beside the RPC layer
//! and never touches orcad's canonical daemon socket path.

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// How much output a session retains for attach snapshots and
/// `terminal.read`. Output past this is dropped oldest-first and
/// counted, so a reader can tell the snapshot is partial.
const OUTPUT_BUFFER_CAP: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Running,
    Exited,
}

pub struct SessionInfo {
    pub id: String,
    pub state: SessionState,
    pub cols: u16,
    pub rows: u16,
    /// Total output bytes ever produced (the stream sequence).
    pub output_seq: u64,
    /// Bytes dropped from the front of the retained buffer.
    pub dropped: u64,
}

struct OutputBuffer {
    chunks: VecDeque<Vec<u8>>,
    retained: usize,
    seq: u64,
    dropped: u64,
}

impl OutputBuffer {
    fn new() -> OutputBuffer {
        OutputBuffer { chunks: VecDeque::new(), retained: 0, seq: 0, dropped: 0 }
    }

    fn push(&mut self, data: &[u8]) {
        self.seq += data.len() as u64;
        self.chunks.push_back(data.to_vec());
        self.retained += data.len();
        while self.retained > OUTPUT_BUFFER_CAP {
            let Some(front) = self.chunks.pop_front() else { break };
            self.retained -= front.len();
            self.dropped += front.len() as u64;
        }
    }

    /// The retained output from byte offset `from` (clamped to
    /// what is still retained) plus the offset it starts at.
    fn read_from(&self, from: u64) -> (u64, Vec<u8>) {
        let start = from.max(self.dropped).min(self.seq);
        let mut skip = (start - self.dropped) as usize;
        let mut out = Vec::new();
        for chunk in &self.chunks {
            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }
            out.extend_from_slice(&chunk[skip..]);
            skip = 0;
        }
        (start, out)
    }
}

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    output: Arc<Mutex<OutputBuffer>>,
    state: Arc<Mutex<SessionState>>,
    cols: u16,
    rows: u16,
}

/// Caller-supplied facts about a session (which workspace it
/// belongs to, its title) that the PTY itself cannot know.
#[derive(Clone, Default)]
pub struct SessionMeta {
    pub worktree: Option<String>,
    pub cwd: Option<String>,
    pub title: Option<String>,
    pub created_at_ms: u64,
}

pub struct PtyManager {
    sessions: HashMap<String, Session>,
    meta: HashMap<String, SessionMeta>,
}

impl PtyManager {
    pub fn new() -> PtyManager {
        PtyManager { sessions: HashMap::new(), meta: HashMap::new() }
    }

    pub fn set_meta(&mut self, session_id: &str, meta: SessionMeta) {
        self.meta.insert(session_id.to_string(), meta);
    }

    pub fn meta(&self, session_id: &str) -> Option<&SessionMeta> {
        self.meta.get(session_id)
    }

    /// Spawns `command` (or the platform default shell) in a new
    /// PTY. Errors if the session id is already in use.
    pub fn spawn(
        &mut self,
        session_id: &str,
        cols: u16,
        rows: u16,
        cwd: Option<&str>,
        command: Option<&str>,
        env: Option<&[(String, String)]>,
    ) -> Result<(), String> {
        if self.sessions.contains_key(session_id) {
            return Err(format!("session already exists: {session_id}"));
        }
        let pair = native_pty_system()
            .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| format!("openpty: {e}"))?;
        let mut builder = match command {
            Some(command) => {
                let shell = default_shell();
                let mut builder = CommandBuilder::new(&shell);
                builder.args([shell_flag(&shell), command]);
                builder
            }
            None => CommandBuilder::new(default_shell()),
        };
        if let Some(cwd) = cwd {
            builder.cwd(cwd);
        }
        if let Some(env) = env {
            for (key, value) in env {
                builder.env(key, value);
            }
        }
        let child = pair
            .slave
            .spawn_command(builder)
            .map_err(|e| format!("spawn: {e}"))?;
        drop(pair.slave);
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("clone reader: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("take writer: {e}"))?;
        let output = Arc::new(Mutex::new(OutputBuffer::new()));
        let state = Arc::new(Mutex::new(SessionState::Running));
        let pump_output = output.clone();
        let pump_state = state.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut output) = pump_output.lock() {
                            output.push(&buf[..n]);
                        }
                    }
                }
            }
            if let Ok(mut state) = pump_state.lock() {
                *state = SessionState::Exited;
            }
        });
        self.sessions.insert(
            session_id.to_string(),
            Session {
                master: pair.master,
                writer,
                child,
                output,
                state,
                cols,
                rows,
            },
        );
        Ok(())
    }

    pub fn write(&mut self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let session = self.session(session_id)?;
        session
            .writer
            .write_all(data)
            .map_err(|e| format!("write: {e}"))?;
        session.writer.flush().map_err(|e| format!("flush: {e}"))
    }

    pub fn resize(&mut self, session_id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let session = self.session(session_id)?;
        session
            .master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| format!("resize: {e}"))?;
        session.cols = cols;
        session.rows = rows;
        Ok(())
    }

    pub fn kill(&mut self, session_id: &str) -> Result<(), String> {
        let mut session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        self.meta.remove(session_id);
        let _ = session.child.kill();
        let _ = session.child.wait();
        Ok(())
    }

    /// Retained output from byte offset `from`: (start offset,
    /// bytes, current sequence end).
    pub fn read(&self, session_id: &str, from: u64) -> Result<(u64, Vec<u8>, u64), String> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        let output = session.output.lock().map_err(|_| "output lock".to_string())?;
        let (start, bytes) = output.read_from(from);
        Ok((start, bytes, output.seq))
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|(id, session)| {
                let output = session.output.lock().ok();
                SessionInfo {
                    id: id.clone(),
                    state: session.state.lock().map(|s| *s).unwrap_or(SessionState::Exited),
                    cols: session.cols,
                    rows: session.rows,
                    output_seq: output.as_ref().map(|o| o.seq).unwrap_or(0),
                    dropped: output.as_ref().map(|o| o.dropped).unwrap_or(0),
                }
            })
            .collect()
    }

    fn session(&mut self, session_id: &str) -> Result<&mut Session, String> {
        self.sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))
    }
}

fn default_shell() -> String {
    if cfg!(windows) {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

fn shell_flag(shell: &str) -> &'static str {
    if cfg!(windows) && !shell.contains("powershell") && !shell.contains("pwsh") {
        "/c"
    } else {
        "-c"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(manager: &PtyManager, id: &str, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (_, bytes, _) = manager.read(id, 0).unwrap();
            let text = String::from_utf8_lossy(&bytes).to_string();
            if text.contains(needle) || Instant::now() > deadline {
                return text;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn spawn_write_read_resize_kill() {
        let mut manager = PtyManager::new();
        manager.spawn("s1", 80, 24, None, None, None).unwrap();
        manager.write("s1", b"echo daemon-rs-marker\n").unwrap();
        let text = wait_for(&manager, "s1", "daemon-rs-marker");
        assert!(text.contains("daemon-rs-marker"), "output was: {text}");
        manager.resize("s1", 120, 40).unwrap();
        let infos = manager.list();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].cols, 120);
        assert_eq!(infos[0].rows, 40);
        assert!(infos[0].output_seq > 0);
        assert!(manager.spawn("s1", 80, 24, None, None, None).is_err());
        manager.kill("s1").unwrap();
        assert!(manager.list().is_empty());
        assert!(manager.write("s1", b"x").is_err());
    }

    #[test]
    fn command_runs_and_exit_is_tracked() {
        let mut manager = PtyManager::new();
        manager
            .spawn("once", 80, 24, None, Some("echo one-shot-done"), None)
            .unwrap();
        let text = wait_for(&manager, "once", "one-shot-done");
        assert!(text.contains("one-shot-done"), "output was: {text}");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let infos = manager.list();
            if infos[0].state == SessionState::Exited || Instant::now() > deadline {
                assert_eq!(infos[0].state, SessionState::Exited);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        manager.kill("once").unwrap();
    }
}
