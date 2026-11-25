//! Session graph subset (Fase 3 M4 slice 3b step 4): the tab
//! state the web client renders panes from. Upstream's graph is
//! the runtime's core state machine (per-worktree snapshots of
//! typed tabs, groups, layout trees, epochs). daemon-rs keeps
//! the flat degenerate case honestly: one group per worktree,
//! terminal tabs only, each tab a single leaf whose `terminal`
//! is the PTY handle the multiplex attaches to.
//!
//! Shapes mirror RuntimeMobileSessionTabsResult /
//! RuntimeMobileSessionTerminalClientTab in
//! src/shared/remote-runtime/session-graph/. Snapshot versions
//! bump on every mutation; the publication epoch is minted per
//! worktree at first use. Streaming updates (subscribe emits)
//! are approximated by answering with the current snapshot —
//! the client re-lists on reconnect.

use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone)]
struct TerminalTab {
    id: String,
    leaf_id: String,
    title: String,
    /// PTY session id (the multiplex subscribe handle).
    terminal: String,
    cwd: Option<String>,
    /// TuiAgent id when this tab hosts an agent session (M5);
    /// published as `launchAgent` like upstream's terminal tabs.
    launch_agent: Option<String>,
}

struct WorktreeGraph {
    epoch: String,
    group_id: String,
    version: u64,
    tabs: Vec<TerminalTab>,
    active_tab_id: Option<String>,
}

impl WorktreeGraph {
    fn new() -> WorktreeGraph {
        WorktreeGraph {
            epoch: crate::registry::uuid(),
            group_id: crate::registry::uuid(),
            version: 0,
            tabs: Vec::new(),
            active_tab_id: None,
        }
    }

    fn snapshot(&self, worktree: &str) -> Value {
        let tabs: Vec<Value> = self
            .tabs
            .iter()
            .map(|tab| {
                let mut value = json!({
                    "type": "terminal",
                    "id": tab.id,
                    "title": tab.title,
                    "parentTabId": tab.id,
                    "leafId": tab.leaf_id,
                    "ptyId": tab.terminal,
                    "status": "ready",
                    "terminal": tab.terminal,
                    "isActive": self.active_tab_id.as_deref() == Some(tab.id.as_str()),
                });
                if let Some(cwd) = &tab.cwd {
                    value["startupCwd"] = json!(cwd);
                }
                if let Some(agent) = &tab.launch_agent {
                    value["launchAgent"] = json!(agent);
                }
                value
            })
            .collect();
        json!({
            "worktree": worktree,
            "publicationEpoch": self.epoch,
            "snapshotVersion": self.version,
            "activeGroupId": if self.tabs.is_empty() { Value::Null } else { json!(self.group_id) },
            "activeTabId": self.active_tab_id,
            "activeTabType": if self.active_tab_id.is_some() { json!("terminal") } else { Value::Null },
            "tabGroups": [{
                "id": self.group_id,
                "activeTabId": self.active_tab_id,
                "tabOrder": self.tabs.iter().map(|tab| tab.id.clone()).collect::<Vec<_>>(),
            }],
            "tabs": tabs,
        })
    }
}

/// The placeholder snapshot for a worktree the graph has never
/// seen (upstream's unpublished epoch is the literal 'none').
fn empty_snapshot(worktree: &str) -> Value {
    json!({
        "worktree": worktree,
        "publicationEpoch": "none",
        "snapshotVersion": 0,
        "activeGroupId": Value::Null,
        "activeTabId": Value::Null,
        "activeTabType": Value::Null,
        "tabs": [],
    })
}

#[derive(Default)]
pub struct Graph {
    worktrees: HashMap<String, WorktreeGraph>,
    /// createAgentSession idempotency: clientOperationId ->
    /// terminal handle (upstream replays the original create).
    agent_ops: HashMap<String, String>,
}

impl Graph {
    pub fn new() -> Graph {
        Graph::default()
    }

    /// Adds a terminal tab to the worktree and activates it.
    /// Returns the tab id and the worktree's new snapshot.
    pub fn add_terminal(
        &mut self,
        worktree: &str,
        title: String,
        terminal: String,
        cwd: Option<String>,
    ) -> (String, Value) {
        self.add_terminal_inner(worktree, title, terminal, cwd, None)
    }

    /// add_terminal for an agent session tab (M5): the tab
    /// carries `launchAgent` in its snapshot.
    pub fn add_agent_terminal(
        &mut self,
        worktree: &str,
        title: String,
        terminal: String,
        cwd: Option<String>,
        agent: String,
    ) -> (String, Value) {
        self.add_terminal_inner(worktree, title, terminal, cwd, Some(agent))
    }

    fn add_terminal_inner(
        &mut self,
        worktree: &str,
        title: String,
        terminal: String,
        cwd: Option<String>,
        launch_agent: Option<String>,
    ) -> (String, Value) {
        let graph = self.worktrees.entry(worktree.to_string()).or_insert_with(WorktreeGraph::new);
        let tab = TerminalTab {
            id: crate::registry::uuid(),
            leaf_id: crate::registry::uuid(),
            title,
            terminal,
            cwd,
            launch_agent,
        };
        let tab_id = tab.id.clone();
        graph.tabs.push(tab);
        graph.active_tab_id = Some(tab_id.clone());
        graph.version += 1;
        let snapshot = graph.snapshot(worktree);
        (tab_id, snapshot)
    }

    /// The terminal handle a createAgentSession operation
    /// already produced, if it was seen before.
    pub fn agent_op_terminal(&self, operation_id: &str) -> Option<String> {
        self.agent_ops.get(operation_id).cloned()
    }

    pub fn record_agent_op(&mut self, operation_id: String, terminal: String) {
        self.agent_ops.insert(operation_id, terminal);
    }

    /// Removes a tab. Returns the PTY handle to retire and the
    /// worktree's new snapshot, or None for an unknown tab.
    pub fn close_tab(&mut self, worktree: &str, tab_id: &str) -> Option<(String, Value)> {
        let graph = self.worktrees.get_mut(worktree)?;
        let index = graph.tabs.iter().position(|tab| tab.id == tab_id)?;
        let removed = graph.tabs.remove(index);
        if graph.active_tab_id.as_deref() == Some(tab_id) {
            graph.active_tab_id = graph.tabs.last().map(|tab| tab.id.clone());
        }
        graph.version += 1;
        let snapshot = graph.snapshot(worktree);
        Some((removed.terminal, snapshot))
    }

    pub fn snapshot(&self, worktree: &str) -> Value {
        match self.worktrees.get(worktree) {
            Some(graph) => graph.snapshot(worktree),
            None => empty_snapshot(worktree),
        }
    }

    /// listAll's inventory: one snapshot per known worktree.
    pub fn inventory(&self) -> Value {
        let snapshots: Vec<Value> = self
            .worktrees
            .iter()
            .map(|(worktree, graph)| graph.snapshot(worktree))
            .collect();
        json!({ "snapshots": snapshots })
    }

    /// (live tabs, live leaves) for status.get — identical in
    /// the flat model, where every tab is a single leaf.
    pub fn counts(&self) -> (u64, u64) {
        let tabs: u64 = self.worktrees.values().map(|graph| graph.tabs.len() as u64).sum();
        (tabs, tabs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_snapshot_close_cycle() {
        let mut graph = Graph::new();
        assert_eq!(graph.snapshot("wt")["publicationEpoch"], "none");
        let (tab_id, snapshot) = graph.add_terminal(
            "wt",
            "Terminal".to_string(),
            "term-1".to_string(),
            Some("/tmp".to_string()),
        );
        assert_eq!(snapshot["snapshotVersion"], 1);
        assert_eq!(snapshot["activeTabId"], tab_id);
        assert_eq!(snapshot["activeTabType"], "terminal");
        let tab = &snapshot["tabs"][0];
        assert_eq!(tab["type"], "terminal");
        assert_eq!(tab["status"], "ready");
        assert_eq!(tab["terminal"], "term-1");
        assert_eq!(tab["isActive"], true);
        assert_eq!(graph.counts(), (1, 1));
        assert_eq!(graph.inventory()["snapshots"].as_array().unwrap().len(), 1);
        let (handle, snapshot) = graph.close_tab("wt", &tab_id).unwrap();
        assert_eq!(handle, "term-1");
        assert_eq!(snapshot["tabs"].as_array().unwrap().len(), 0);
        assert_eq!(snapshot["activeTabId"], Value::Null);
        assert!(graph.close_tab("wt", &tab_id).is_none());
        assert_eq!(graph.counts(), (0, 0));
    }
}
