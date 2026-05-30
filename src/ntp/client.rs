use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpClientConfig {
    pub enabled: bool,
    pub server: String,
    pub interval_secs: u64,
}

impl Default for NtpClientConfig {
    fn default() -> Self { Self { enabled: false, server: "pool.ntp.org".into(), interval_secs: 3600 } }
}

pub struct NtpClient { config: Mutex<NtpClientConfig> }

impl NtpClient {
    pub fn new() -> Self { Self { config: Mutex::new(NtpClientConfig::default()) } }
    pub fn get_config(&self) -> NtpClientConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: NtpClientConfig) { *self.config.lock().unwrap() = c; }
    pub async fn sync(&self) -> Result<String> {
        let cfg = self.get_config();
        let output = Command::new("ntpdate")
            .args(["-q", &cfg.server])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for NtpClient { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_default_config() {
        let client = NtpClient::new();
        assert_eq!(client.get_config().interval_secs, 3600);
    }
}
