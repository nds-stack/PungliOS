use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyArpEntry {
    pub interface: String,
    pub ip: IpAddr,
    pub enabled: bool,
}

pub struct ProxyArpManager { entries: Mutex<Vec<ProxyArpEntry>> }

impl ProxyArpManager {
    pub fn new() -> Self { Self { entries: Mutex::new(Vec::new()) } }
    pub fn add(&self, e: ProxyArpEntry) { self.entries.lock().unwrap().push(e); }
    pub fn remove(&self, idx: usize) { self.entries.lock().unwrap().remove(idx); }
    pub fn list(&self) -> Vec<ProxyArpEntry> { self.entries.lock().unwrap().clone() }
}

impl Default for ProxyArpManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_proxy_arp() {
        let m = ProxyArpManager::new();
        m.add(ProxyArpEntry { interface: "bridge".into(), ip: "10.0.0.1".parse().unwrap(), enabled: true });
        assert_eq!(m.list().len(), 1);
    }
}
