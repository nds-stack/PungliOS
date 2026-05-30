use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRelayConfig {
    pub name: String,
    pub interfaces: Vec<String>,
    pub server: Ipv4Addr,
    pub enabled: bool,
}

pub struct DhcpRelayManager {
    relays: Mutex<Vec<DhcpRelayConfig>>,
}

impl DhcpRelayManager {
    pub fn new() -> Self { Self { relays: Mutex::new(Vec::new()) } }
    pub fn add(&self, relay: DhcpRelayConfig) -> Result<()> {
        if relay.name.is_empty() { bail!("name required"); }
        if relay.interfaces.is_empty() { bail!("at least one interface required"); }
        self.relays.lock().unwrap().push(relay);
        Ok(())
    }
    pub fn remove(&self, name: &str) -> Result<()> {
        let mut relays = self.relays.lock().unwrap();
        let len = relays.len();
        relays.retain(|r| r.name != name);
        if relays.len() == len { bail!("relay {name} not found"); }
        Ok(())
    }
    pub fn list(&self) -> Vec<DhcpRelayConfig> { self.relays.lock().unwrap().clone() }
}

impl Default for DhcpRelayManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_relay_add_list() {
        let mgr = DhcpRelayManager::new();
        mgr.add(DhcpRelayConfig {
            name: "relay1".into(), interfaces: vec!["eth1".into(), "eth2".into()],
            server: "192.168.1.1".parse().unwrap(), enabled: true,
        }).unwrap();
        assert_eq!(mgr.list().len(), 1);
    }
}
