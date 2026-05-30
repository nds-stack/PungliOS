use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StpMode { Stp, Rstp, Mstp }
impl std::fmt::Display for StpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Stp => write!(f, "stp"), Self::Rstp => write!(f, "rstp"), Self::Mstp => write!(f, "mstp") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StpConfig {
    pub bridge: String,
    pub enabled: bool,
    pub mode: StpMode,
    pub priority: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
}

pub struct StpManager { configs: Mutex<Vec<StpConfig>> }

impl StpManager {
    pub fn new() -> Self { Self { configs: Mutex::new(Vec::new()) } }
    pub fn set(&self, config: StpConfig) -> Result<()> {
        if config.bridge.is_empty() { bail!("bridge name required"); }
        let mut configs = self.configs.lock().unwrap();
        if let Some(existing) = configs.iter_mut().find(|c| c.bridge == config.bridge) {
            *existing = config;
        } else { configs.push(config); }
        Ok(())
    }
    pub fn get(&self, bridge: &str) -> Option<StpConfig> {
        self.configs.lock().unwrap().iter().find(|c| c.bridge == bridge).cloned()
    }
    pub fn list(&self) -> Vec<StpConfig> { self.configs.lock().unwrap().clone() }
}

impl Default for StpManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_stp_config() {
        let mgr = StpManager::new();
        mgr.set(StpConfig {
            bridge: "br0".into(), enabled: true, mode: StpMode::Rstp,
            priority: 32768, max_age: 20, hello_time: 2, forward_delay: 15,
        }).unwrap();
        assert_eq!(mgr.get("br0").unwrap().mode, StpMode::Rstp);
    }
}
