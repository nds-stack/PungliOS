use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub enabled: bool,
    pub path: String,
    pub upload_url: Option<String>,
    pub keep_count: u32,
    pub schedule_cron: String,
}

impl Default for BackupConfig {
    fn default() -> Self { Self { enabled: false, path: "/etc/punglios/backup".into(), upload_url: None, keep_count: 7, schedule_cron: "0 3 * * *".into() } }
}

pub struct BackupManager { config: Mutex<BackupConfig> }

impl BackupManager {
    pub fn new() -> Self { Self { config: Mutex::new(BackupConfig::default()) } }
    pub fn get_config(&self) -> BackupConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: BackupConfig) { *self.config.lock().unwrap() = c; }
    pub async fn run_backup(&self) -> Result<String> {
        let cfg = self.get_config();
        let output = Command::new("cp").args(["/etc/punglios/config.yaml", &cfg.path]).output().await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for BackupManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_config() {
        let mgr = BackupManager::new();
        assert_eq!(mgr.get_config().keep_count, 7);
    }
}
