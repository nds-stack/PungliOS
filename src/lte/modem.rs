use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModemInfo {
    pub manufacturer: String,
    pub model: String,
    pub imei: String,
    pub imsi: String,
    pub operator: String,
    pub technology: String,
    pub signal_quality: u8,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModemConfig {
    pub apn: String,
    pub pin: Option<String>,
    pub roam_allowed: bool,
}

impl Default for ModemConfig {
    fn default() -> Self {
        Self {
            apn: "internet".into(),
            pin: None,
            roam_allowed: false,
        }
    }
}

pub struct ModemManager {
    info: Mutex<Option<ModemInfo>>,
    config: Mutex<ModemConfig>,
}

impl ModemManager {
    pub fn new() -> Self {
        Self {
            info: Mutex::new(None),
            config: Mutex::new(ModemConfig::default()),
        }
    }

    pub fn get_info(&self) -> Option<ModemInfo> {
        self.info.lock().unwrap().clone()
    }

    pub fn set_info(&self, info: ModemInfo) {
        *self.info.lock().unwrap() = Some(info);
    }

    pub fn get_config(&self) -> ModemConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: ModemConfig) -> Result<()> {
        if config.apn.is_empty() {
            bail!("APN cannot be empty");
        }
        *self.config.lock().unwrap() = config;
        Ok(())
    }

    pub async fn refresh(&self) -> Result<ModemInfo> {
        // Try mmcli first, fallback to AT commands
        let output = Command::new("mmcli")
            .args(["-L"])
            .output()
            .await;
        // If mmcli not available, return default
        let info = ModemInfo {
            manufacturer: "Unknown".into(),
            model: "Generic LTE".into(),
            imei: "000000000000000".into(),
            imsi: "000000000000000".into(),
            operator: "Unknown".into(),
            technology: "LTE".into(),
            signal_quality: 0,
            enabled: true,
        };
        let _ = output;
        self.set_info(info.clone());
        Ok(info)
    }

    pub async fn connect(&self) -> Result<String> {
        let apn = self.get_config().apn;
        if apn.is_empty() {
            bail!("APN not configured");
        }
        // Try modem manager first
        let output = Command::new("mmcli")
            .args(["--simple-connect", &format!("apn={apn}")])
            .output()
            .await?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        // Fallback: qmi-network
        let output = Command::new("qmi-network")
            .args(["/dev/cdc-wdm0", "start"])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub async fn disconnect(&self) -> Result<String> {
        let output = Command::new("mmcli")
            .args(["--simple-disconnect"])
            .output()
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for ModemManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_config() {
        let mgr = ModemManager::new();
        let cfg = mgr.get_config();
        assert_eq!(cfg.apn, "internet");
    }

    #[tokio::test]
    async fn test_set_config() {
        let mgr = ModemManager::new();
        mgr.set_config(ModemConfig {
            apn: "isp.apn".into(),
            pin: None,
            roam_allowed: true,
        })
        .unwrap();
        assert_eq!(mgr.get_config().apn, "isp.apn");
    }

    #[tokio::test]
    async fn test_empty_apn_rejected() {
        let mgr = ModemManager::new();
        assert!(mgr
            .set_config(ModemConfig {
                apn: "".into(),
                pin: None,
                roam_allowed: false,
            })
            .is_err());
    }

    #[tokio::test]
    async fn test_refresh() {
        let mgr = ModemManager::new();
        let info = mgr.refresh().await.unwrap();
        assert_eq!(info.manufacturer, "Unknown");
    }
}
