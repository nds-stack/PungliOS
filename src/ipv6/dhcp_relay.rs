use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcpv6RelayConfig {
    pub name: String,
    pub interfaces: Vec<String>,
    pub server: String,
    pub enabled: bool,
}

pub struct Dhcpv6RelayManager { relays: Mutex<Vec<Dhcpv6RelayConfig>> }

impl Dhcpv6RelayManager {
    pub fn new() -> Self { Self { relays: Mutex::new(Vec::new()) } }
    pub fn add(&self, r: Dhcpv6RelayConfig) -> Result<()> {
        if r.name.is_empty() { bail!("name required"); }
        self.relays.lock().unwrap().push(r); Ok(())
    }
    pub fn remove(&self, name: &str) { self.relays.lock().unwrap().retain(|r| r.name != name); }
    pub fn list(&self) -> Vec<Dhcpv6RelayConfig> { self.relays.lock().unwrap().clone() }
}

impl Default for Dhcpv6RelayManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dhcpv6_relay() {
        let m = Dhcpv6RelayManager::new();
        m.add(Dhcpv6RelayConfig { name: "relay1".into(), interfaces: vec!["eth0".into()], server: "2001:db8::1".into(), enabled: true }).unwrap();
        assert_eq!(m.list().len(), 1);
    }
}
