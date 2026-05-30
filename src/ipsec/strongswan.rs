use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecConfig {
    pub enabled: bool,
    pub charon_port: u16,
}

impl Default for IpsecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            charon_port: 4500,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpsecConnection {
    pub name: String,
    pub status: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub local_id: Option<String>,
    pub remote_id: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct IpsecManager {
    config: std::sync::Mutex<IpsecConfig>,
}

impl IpsecManager {
    pub fn new() -> Self {
        Self {
            config: std::sync::Mutex::new(IpsecConfig::default()),
        }
    }

    pub fn get_config(&self) -> IpsecConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: IpsecConfig) -> Result<()> {
        let mut c = self.config.lock().unwrap();
        *c = config;
        Ok(())
    }

    pub async fn connect(&self, profile: &str) -> Result<String> {
        if profile.is_empty() {
            bail!("profile name cannot be empty");
        }
        let output = Command::new("ipsec")
            .args(["up", profile])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("ipsec up failed: {stderr}");
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub async fn disconnect(&self, profile: &str) -> Result<String> {
        if profile.is_empty() {
            bail!("profile name cannot be empty");
        }
        let output = Command::new("ipsec")
            .args(["down", profile])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub async fn status(&self) -> Result<Vec<IpsecConnection>> {
        let output = Command::new("swanctl")
            .args(["--list-sas"])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut conns = Vec::new();

        for line in stdout.lines() {
            if line.contains(": ESTABLISHED") || line.contains(": CONNECTING") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim_end_matches(':').to_string();
                    let status = parts
                        .get(1)
                        .copied()
                        .unwrap_or("unknown")
                        .trim_end_matches(':')
                        .to_string();
                    conns.push(IpsecConnection {
                        name,
                        status,
                        local_ip: String::new(),
                        remote_ip: String::new(),
                        local_id: None,
                        remote_id: None,
                        bytes_in: 0,
                        bytes_out: 0,
                    });
                }
            }
        }
        Ok(conns)
    }

    pub async fn reload(&self) -> Result<String> {
        let output = Command::new("ipsec")
            .args(["reload"])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for IpsecManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_empty_fails() {
        let mgr = IpsecManager::new();
        assert!(mgr.connect("").await.is_err());
    }

    #[tokio::test]
    async fn test_default_config() {
        let mgr = IpsecManager::new();
        let cfg = mgr.get_config();
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_set_config() {
        let mgr = IpsecManager::new();
        mgr.set_config(IpsecConfig {
            enabled: true,
            charon_port: 4500,
        })
        .unwrap();
        assert!(mgr.get_config().enabled);
    }
}
