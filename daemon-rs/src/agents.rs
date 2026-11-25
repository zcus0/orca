//! TUI agent catalog + launch/resume commands (Fase 3 M5).
//! Mirrors the subset of upstream's TuiAgent catalog
//! (src/shared/agent-launch/catalog/tui-agent.ts) whose CLI is a
//! plain executable, and the resume argv rules in
//! agent-resume-argv.ts for the agents daemon-rs supports
//! resuming. The agent runs as a TUI inside a PTY — the graph
//! publishes it as a terminal tab with `launchAgent` set.

/// Executable for a TuiAgent id, for the agents that are a
/// single CLI binary. None = unknown/unsupported in the subset.
pub fn agent_executable(agent: &str) -> Option<&'static str> {
    Some(match agent {
        "claude" | "claude-agent-teams" | "openclaude" => "claude",
        "codex" => "codex",
        "opencode" => "opencode",
        "opencode2" => "opencode2",
        "pi" => "pi",
        "omp" => "omp",
        "aider" => "aider",
        "gemini" => "gemini",
        "goose" => "goose",
        "amp" => "amp",
        "crush" => "crush",
        "cline" => "cline",
        "continue" => "cn",
        "cursor" => "cursor-agent",
        "kimi" => "kimi",
        "qwen-code" => "qwen",
        "hermes" => "hermes",
        "copilot" => "copilot",
        "grok" => "grok",
        "mistral-vibe" => "vibe",
        "codebuddy" => "codebuddy",
        "mimo-code" => "mimo",
        _ => return None,
    })
}

/// Builds the shell command line for a fresh agent launch:
/// the executable plus the client's raw argument strings
/// (upstream treats agentArgs/extraAgentArgs as raw strings).
pub fn launch_command(agent: &str, agent_args: Option<&str>, extra_args: Option<&str>) -> Option<String> {
    let exe = agent_executable(agent)?;
    let mut command = exe.to_string();
    for args in [agent_args, extra_args] {
        if let Some(args) = args.map(str::trim).filter(|args| !args.is_empty()) {
            command.push(' ');
            command.push_str(args);
        }
    }
    Some(command)
}

/// Resume argv for ensureAgentSession (kind 'explicit'),
/// mirroring getAgentResumeArgv for the supported agents.
/// `key` is the provider session key ('session_id' or
/// 'conversation_id'); `transcript_path` feeds pi/omp.
pub fn resume_command(
    agent: &str,
    key: &str,
    id: &str,
    transcript_path: Option<&str>,
) -> Option<String> {
    let argv: Vec<String> = match agent {
        "claude" | "claude-agent-teams" | "openclaude" => {
            if key != "session_id" {
                return None;
            }
            vec!["claude".into(), "--resume".into(), id.into()]
        }
        "codex" => {
            if key != "session_id" {
                return None;
            }
            vec!["codex".into(), "resume".into(), id.into()]
        }
        "opencode" => {
            if key != "session_id" {
                return None;
            }
            vec!["opencode".into(), "--session".into(), id.into()]
        }
        "opencode2" => {
            if key != "session_id" {
                return None;
            }
            vec!["opencode2".into(), "--session".into(), id.into()]
        }
        "pi" => {
            let path = transcript_path.filter(|path| !path.trim().is_empty())?;
            vec!["pi".into(), "--session".into(), path.into()]
        }
        "omp" => {
            let target = transcript_path.filter(|path| !path.trim().is_empty()).unwrap_or(id);
            vec!["omp".into(), "--resume".into(), target.into()]
        }
        _ => return None,
    };
    Some(shell_join(&argv))
}

/// Joins argv into one shell command line, single-quoting any
/// argument that is not plain [A-Za-z0-9_./:=+-] text.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_./:=+-".contains(c))
            {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_and_launch() {
        assert_eq!(agent_executable("claude"), Some("claude"));
        assert_eq!(agent_executable("omp"), Some("omp"));
        assert_eq!(agent_executable("nope"), None);
        assert_eq!(
            launch_command("codex", Some("--full-auto"), None).unwrap(),
            "codex --full-auto"
        );
        assert_eq!(launch_command("claude", None, Some("--debug")).unwrap(), "claude --debug");
        assert!(launch_command("nope", None, None).is_none());
    }

    #[test]
    fn resume_argv() {
        assert_eq!(
            resume_command("claude", "session_id", "abc-123", None).unwrap(),
            "claude --resume abc-123"
        );
        assert!(resume_command("claude", "conversation_id", "abc", None).is_none());
        assert_eq!(
            resume_command("codex", "session_id", "s1", None).unwrap(),
            "codex resume s1"
        );
        assert_eq!(
            resume_command("pi", "session_id", "s1", Some("/tmp/t.jsonl")).unwrap(),
            "pi --session /tmp/t.jsonl"
        );
        assert!(resume_command("pi", "session_id", "s1", None).is_none());
        assert_eq!(
            resume_command("omp", "session_id", "s1", None).unwrap(),
            "omp --resume s1"
        );
    }
}
