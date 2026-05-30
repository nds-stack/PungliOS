use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BfdSession {
    pub neighbor: String,
    pub interface: String,
    pub desired_tx_interval: u32,
    pub required_rx_interval: u32,
    pub detection_multiplier: u8,
    pub state: String,
    pub last_seen: u64,
    pub enabled: bool,
}

pub struct BfdManager { sessions: Mutex<HashMap<String, BfdSession>> }

impl BfdManager {
    pub fn new() -> Self { Self { sessions: Mutex::new(HashMap::new()) } }
    pub fn add(&self, session: BfdSession) -> Result<()> {
        if session.neighbor.is_empty() { bail!("neighbor required"); }
        self.sessions.lock().unwrap().insert(session.neighbor.clone(), session);
        Ok(())
    }
    pub fn remove(&self, neighbor: &str) -> Result<()> {
        self.sessions.lock().unwrap().remove(neighbor);
        Ok(())
    }
    pub fn list(&self) -> Vec<BfdSession> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }
    pub fn is_down(&self, neighbor: &str, timeout_secs: u64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.sessions.lock().unwrap().get(neighbor).map_or(true, |s| {
            now.saturating_sub(s.last_seen) > timeout_secs || !s.enabled
        })
    }
}

impl Default for BfdManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bfd_add() {
        let mgr = BfdManager::new();
        mgr.add(BfdSession {
            neighbor: "10.0.0.1".into(), interface: "eth0".into(),
            desired_tx_interval: 100, required_rx_interval: 100,
            detection_multiplier: 3, state: "up".into(),
            last_seen: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            enabled: true,
        }).unwrap();
        assert_eq!(mgr.list().len(), 1);
    }
}
