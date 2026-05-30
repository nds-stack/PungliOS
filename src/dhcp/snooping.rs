use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpSnoopingConfig {
    pub bridge: String,
    pub enabled: bool,
    pub trusted_ports: Vec<String>,
    pub verify_mac: bool,
}

pub struct DhcpSnooping { configs: Mutex<Vec<DhcpSnoopingConfig>> }

impl DhcpSnooping {
    pub fn new() -> Self { Self { configs: Mutex::new(Vec::new()) } }
    pub fn set(&self, config: DhcpSnoopingConfig) {
        let mut configs = self.configs.lock().unwrap();
        if let Some(existing) = configs.iter_mut().find(|c| c.bridge == config.bridge) {
            *existing = config;
        } else { configs.push(config); }
    }
    pub fn list(&self) -> Vec<DhcpSnoopingConfig> { self.configs.lock().unwrap().clone() }
}

impl Default for DhcpSnooping { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_snooping() {
        let s = DhcpSnooping::new();
        s.set(DhcpSnoopingConfig {
            bridge: "br0".into(), enabled: true,
            trusted_ports: vec!["eth0".into()], verify_mac: true,
        });
        assert_eq!(s.list().len(), 1);
    }
}
