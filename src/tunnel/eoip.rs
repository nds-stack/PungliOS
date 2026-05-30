use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EoipTunnel {
    pub name: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub tunnel_id: u32,
    pub mtu: u16,
    pub enabled: bool,
}

pub struct EoipManager { tunnels: Mutex<HashMap<String, EoipTunnel>> }

impl EoipManager {
    pub fn new() -> Self { Self { tunnels: Mutex::new(HashMap::new()) } }
    pub fn create(&self, tunnel: EoipTunnel) -> Result<()> {
        if tunnel.name.is_empty() { bail!("name required"); }
        if tunnel.remote_ip.is_empty() { bail!("remote IP required"); }
        let mut tunnels = self.tunnels.lock().unwrap();
        if tunnels.contains_key(&tunnel.name) { bail!("tunnel '{}' exists", tunnel.name); }
        tunnels.insert(tunnel.name.clone(), tunnel);
        Ok(())
    }
    pub fn delete(&self, name: &str) { self.tunnels.lock().unwrap().remove(name); }
    pub fn list(&self) -> Vec<EoipTunnel> { self.tunnels.lock().unwrap().values().cloned().collect() }
}

impl Default for EoipManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_eoip_create() {
        let mgr = EoipManager::new();
        mgr.create(EoipTunnel {
            name: "eoip1".into(), local_ip: "10.0.0.1".into(),
            remote_ip: "10.0.0.2".into(), tunnel_id: 1, mtu: 1500, enabled: true,
        }).unwrap();
        assert_eq!(mgr.list().len(), 1);
    }
}
