use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetwatchAction {
    Log,
    Script(String),
    HttpGet(String),
    RestartService(String),
    EnableInterface(String),
    DisableInterface(String),
    SendEmail(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetwatchStatus {
    Unknown,
    Up,
    Down,
    Flapping,
}

impl std::fmt::Display for NetwatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
            Self::Flapping => write!(f, "flapping"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetwatchEntry {
    pub id: u64,
    pub name: String,
    pub target: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub retries: u32,
    pub action_up: Option<NetwatchAction>,
    pub action_down: Option<NetwatchAction>,
    pub enabled: bool,
    pub status: NetwatchStatus,
    pub last_up: Option<u64>,
    pub last_down: Option<u64>,
    pub consecutive_failures: u32,
    pub response_time_ms: f64,
}

static NEXT_NETWATCH_ID: AtomicU64 = AtomicU64::new(1);

pub struct NetwatchManager {
    entries: Mutex<HashMap<u64, NetwatchEntry>>,
}

impl NetwatchManager {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn add(&self, entry: &NetwatchEntry) -> Result<u64> {
        if entry.name.is_empty() {
            bail!("netwatch name cannot be empty");
        }
        if entry.target.is_empty() {
            bail!("target cannot be empty");
        }
        let id = NEXT_NETWATCH_ID.fetch_add(1, Ordering::SeqCst);
        let mut e = entry.clone();
        e.id = id;
        e.status = NetwatchStatus::Unknown;
        self.entries.lock().unwrap().insert(id, e);
        Ok(id)
    }

    pub fn remove(&self, id: u64) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        entries
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("netwatch {id} not found"))?;
        Ok(())
    }

    pub fn get(&self, id: u64) -> Option<NetwatchEntry> {
        self.entries.lock().unwrap().get(&id).cloned()
    }

    pub fn list(&self) -> Vec<NetwatchEntry> {
        let mut entries: Vec<_> = self.entries.lock().unwrap().values().cloned().collect();
        entries.sort_by_key(|e| e.id);
        entries
    }

    pub fn update_status(&self, id: u64, status: NetwatchStatus, rtt_ms: f64) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            match status {
                NetwatchStatus::Up => {
                    entry.last_up = Some(now);
                    entry.consecutive_failures = 0;
                }
                NetwatchStatus::Down => {
                    entry.last_down = Some(now);
                    entry.consecutive_failures += 1;
                }
                _ => {}
            }
            entry.status = status;
            entry.response_time_ms = rtt_ms;
        }
    }

    pub fn set_enabled(&self, id: u64, enabled: bool) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("netwatch {id} not found"))?;
        entry.enabled = enabled;
        Ok(())
    }

    pub fn get_flapping(&self) -> Vec<NetwatchEntry> {
        self.list()
            .into_iter()
            .filter(|e| e.status == NetwatchStatus::Flapping)
            .collect()
    }

    pub fn get_down(&self) -> Vec<NetwatchEntry> {
        self.list()
            .into_iter()
            .filter(|e| e.status == NetwatchStatus::Down)
            .collect()
    }
}

impl Default for NetwatchManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_list() {
        let mgr = NetwatchManager::new();
        let id = mgr
            .add(&NetwatchEntry {
                id: 0,
                name: "google".into(),
                target: "8.8.8.8".into(),
                interval_secs: 30,
                timeout_secs: 5,
                retries: 3,
                action_up: Some(NetwatchAction::Log),
                action_down: Some(NetwatchAction::Log),
                enabled: true,
                status: NetwatchStatus::Unknown,
                last_up: None,
                last_down: None,
                consecutive_failures: 0,
                response_time_ms: 0.0,
            })
            .unwrap();
        let entries = mgr.list();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].target, "8.8.8.8");

        let entry = mgr.get(id).unwrap();
        assert_eq!(entry.name, "google");
    }

    #[test]
    fn test_update_status() {
        let mgr = NetwatchManager::new();
        let id = mgr
            .add(&NetwatchEntry {
                id: 0,
                name: "test".into(),
                target: "10.0.0.1".into(),
                interval_secs: 10,
                timeout_secs: 3,
                retries: 2,
                action_up: None,
                action_down: None,
                enabled: true,
                status: NetwatchStatus::Unknown,
                last_up: None,
                last_down: None,
                consecutive_failures: 0,
                response_time_ms: 0.0,
            })
            .unwrap();
        mgr.update_status(id, NetwatchStatus::Up, 5.0);
        let entry = mgr.get(id).unwrap();
        assert_eq!(entry.status, NetwatchStatus::Up);
        assert_eq!(entry.response_time_ms, 5.0);
    }

    #[test]
    fn test_remove() {
        let mgr = NetwatchManager::new();
        let id = mgr
            .add(&NetwatchEntry {
                id: 0,
                name: "temp".into(),
                target: "10.0.0.1".into(),
                interval_secs: 10,
                timeout_secs: 3,
                retries: 2,
                action_up: None,
                action_down: None,
                enabled: true,
                status: NetwatchStatus::Unknown,
                last_up: None,
                last_down: None,
                consecutive_failures: 0,
                response_time_ms: 0.0,
            })
            .unwrap();
        mgr.remove(id).unwrap();
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_get_down() {
        let mgr = NetwatchManager::new();
        let id = mgr
            .add(&NetwatchEntry {
                id: 0,
                name: "down-host".into(),
                target: "10.0.0.99".into(),
                interval_secs: 10,
                timeout_secs: 3,
                retries: 2,
                action_up: None,
                action_down: None,
                enabled: true,
                status: NetwatchStatus::Unknown,
                last_up: None,
                last_down: None,
                consecutive_failures: 0,
                response_time_ms: 0.0,
            })
            .unwrap();
        mgr.update_status(id, NetwatchStatus::Down, 0.0);
        assert_eq!(mgr.get_down().len(), 1);
    }
}
