use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolTarget {
    pub name: String,
    pub mac: String,
    pub interface: Option<String>,
    pub broadcast_ip: Option<IpAddr>,
}

pub struct WolManager { targets: Mutex<HashMap<String, WolTarget>> }

impl WolManager {
    pub fn new() -> Self { Self { targets: Mutex::new(HashMap::new()) } }
    pub fn add(&self, target: WolTarget) { self.targets.lock().unwrap().insert(target.name.clone(), target); }
    pub fn remove(&self, name: &str) { self.targets.lock().unwrap().remove(name); }
    pub fn list(&self) -> Vec<WolTarget> { self.targets.lock().unwrap().values().cloned().collect() }
    pub async fn wake(&self, mac: &str) -> Result<String> {
        let output = Command::new("wakeonlan")
            .args([mac])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for WolManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wol() {
        let mgr = WolManager::new();
        mgr.add(WolTarget {
            name: "backup-server".into(), mac: "00:11:22:33:44:55".into(),
            interface: None, broadcast_ip: None,
        });
        assert_eq!(mgr.list().len(), 1);
    }
}
