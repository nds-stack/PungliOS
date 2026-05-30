use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    pub enabled: bool,
    pub service: String,
    pub hostname: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub interval_minutes: u32,
}

impl Default for DdnsConfig { fn default() -> Self { Self { enabled: false, service: "cloudflare".into(), hostname: String::new(), username: None, password: None, interval_minutes: 5 } } }

pub struct DdnsManager { config: Mutex<DdnsConfig> }

impl DdnsManager {
    pub fn new() -> Self { Self { config: Mutex::new(DdnsConfig::default()) } }
    pub fn get_config(&self) -> DdnsConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: DdnsConfig) { *self.config.lock().unwrap() = c; }
    pub async fn update(&self) -> Result<String> {
        let _cfg = self.get_config();
        Ok("ddns update triggered (mock)".into())
    }
}

impl Default for DdnsManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ddns() { let mgr = DdnsManager::new(); assert!(!mgr.get_config().enabled); }
}
