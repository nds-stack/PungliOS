use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpnpMapping {
    pub id: u64,
    pub external_port: u16,
    pub internal_port: u16,
    pub internal_ip: Ipv4Addr,
    pub protocol: String,
    pub duration_secs: u32,
    pub description: String,
}

pub struct UpnpManager { mappings: Mutex<Vec<UpnpMapping>>, enabled: Mutex<bool> }

impl UpnpManager {
    pub fn new() -> Self { Self { mappings: Mutex::new(Vec::new()), enabled: Mutex::new(false) } }
    pub fn set_enabled(&self, val: bool) { *self.enabled.lock().unwrap() = val; }
    pub fn is_enabled(&self) -> bool { *self.enabled.lock().unwrap() }
    pub fn add_mapping(&self, m: UpnpMapping) { self.mappings.lock().unwrap().push(m); }
    pub fn remove_mapping(&self, id: u64) { self.mappings.lock().unwrap().retain(|m| m.id != id); }
    pub fn list_mappings(&self) -> Vec<UpnpMapping> { self.mappings.lock().unwrap().clone() }
}

impl Default for UpnpManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_upnp() {
        let mgr = UpnpManager::new();
        mgr.set_enabled(true);
        mgr.add_mapping(UpnpMapping { id: 1, external_port: 8080, internal_port: 80, internal_ip: "192.168.1.100".parse().unwrap(), protocol: "tcp".into(), duration_secs: 0, description: "web server".into() });
        assert_eq!(mgr.list_mappings().len(), 1);
    }
}
