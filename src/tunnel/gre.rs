use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreTunnel {
    pub name: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub ttl: u8,
    pub mtu: u16,
    pub enabled: bool,
}

pub struct GreManager { tunnels: Mutex<HashMap<String, GreTunnel>> }

impl GreManager {
    pub fn new() -> Self { Self { tunnels: Mutex::new(HashMap::new()) } }
    pub fn create(&self, tunnel: GreTunnel) -> Result<()> {
        if tunnel.name.is_empty() { bail!("name required"); }
        if tunnel.remote_ip.is_empty() { bail!("remote IP required"); }
        let mut tunnels = self.tunnels.lock().unwrap();
        tunnels.insert(tunnel.name.clone(), tunnel);
        Ok(())
    }
    pub fn delete(&self, name: &str) { self.tunnels.lock().unwrap().remove(name); }
    pub fn list(&self) -> Vec<GreTunnel> { self.tunnels.lock().unwrap().values().cloned().collect() }
}

impl Default for GreManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_gre_create() {
        let mgr = GreManager::new();
        mgr.create(GreTunnel {
            name: "gre1".into(), local_ip: "10.0.0.1".into(),
            remote_ip: "10.0.0.2".into(), ttl: 64, mtu: 1476, enabled: true,
        }).unwrap();
        assert!(mgr.list().len() == 1);
    }
}
