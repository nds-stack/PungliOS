use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpConfig {
    pub enabled: bool,
    pub community_ro: String,
    pub community_rw: String,
    pub system_name: String,
    pub system_location: String,
    pub system_contact: String,
    pub listen_port: u16,
    pub allowed_networks: Vec<String>,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            community_ro: "public".into(),
            community_rw: "private".into(),
            system_name: "PungliOS".into(),
            system_location: "Unknown".into(),
            system_contact: "admin@punglios.local".into(),
            listen_port: 161,
            allowed_networks: vec!["0.0.0.0/0".into()],
        }
    }
}

pub struct SnmpAgent {
    config: Mutex<SnmpConfig>,
}

impl SnmpAgent {
    pub fn new() -> Self {
        Self {
            config: Mutex::new(SnmpConfig::default()),
        }
    }

    pub fn get_config(&self) -> SnmpConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: SnmpConfig) -> Result<()> {
        if config.community_ro.is_empty() {
            bail!("read-only community cannot be empty");
        }
        let mut c = self.config.lock().unwrap();
        *c = config;
        Ok(())
    }

    pub fn update_config(&self, patch: SnmpConfig) -> Result<()> {
        let mut config = self.config.lock().unwrap();
        if !patch.community_ro.is_empty() {
            config.community_ro = patch.community_ro;
        }
        if !patch.community_rw.is_empty() {
            config.community_rw = patch.community_rw;
        }
        if !patch.system_name.is_empty() {
            config.system_name = patch.system_name;
        }
        if !patch.system_location.is_empty() {
            config.system_location = patch.system_location;
        }
        if !patch.system_contact.is_empty() {
            config.system_contact = patch.system_contact;
        }
        config.listen_port = patch.listen_port;
        config.enabled = patch.enabled;
        Ok(())
    }
}

impl Default for SnmpAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let agent = SnmpAgent::new();
        let config = agent.get_config();
        assert_eq!(config.community_ro, "public");
        assert!(!config.enabled);
    }

    #[test]
    fn test_set_config() {
        let agent = SnmpAgent::new();
        let config = SnmpConfig {
            enabled: true,
            community_ro: "monitor".into(),
            community_rw: "admin".into(),
            system_name: "Router-1".into(),
            system_location: "Jakarta".into(),
            system_contact: "admin@isp.local".into(),
            listen_port: 161,
            allowed_networks: vec!["10.0.0.0/8".into()],
        };
        agent.set_config(config).unwrap();
        let cfg = agent.get_config();
        assert!(cfg.enabled);
        assert_eq!(cfg.community_ro, "monitor");
    }
}
