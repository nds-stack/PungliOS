use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeConfig {
    pub enabled: bool,
    pub check_interval_hours: u32,
    pub auto_upgrade: bool,
    pub repo_url: String,
    pub current_version: String,
}

impl Default for UpgradeConfig {
    fn default() -> Self { Self { enabled: false, check_interval_hours: 24, auto_upgrade: false, repo_url: "https://github.com/nds-stack/PungliOS/releases".into(), current_version: "0.7.0".into() } }
}

pub struct UpgradeManager { config: Mutex<UpgradeConfig> }

impl UpgradeManager {
    pub fn new() -> Self { Self { config: Mutex::new(UpgradeConfig::default()) } }
    pub fn get_config(&self) -> UpgradeConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: UpgradeConfig) { *self.config.lock().unwrap() = c; }
    pub async fn check(&self) -> Result<String> { Ok("{\"latest\":\"0.7.0\",\"current\":\"0.7.0\"}".into()) }
    pub async fn upgrade(&self) -> Result<String> {
        let output = Command::new("cargo").args(["install", "--git", "https://github.com/nds-stack/PungliOS"]).output().await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for UpgradeManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests { use super::*; #[tokio::test] async fn test_version() { let m = UpgradeManager::new(); assert_eq!(m.get_config().current_version, "0.7.0"); } }
