use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MndpEntry {
    pub identity: String,
    pub version: String,
    pub platform: String,
    pub interface: String,
    pub address: String,
    pub mac: String,
}

pub struct MndpManager { entries: Mutex<Vec<MndpEntry>> }

impl MndpManager {
    pub fn new() -> Self { Self { entries: Mutex::new(Vec::new()) } }
    pub fn add(&self, e: MndpEntry) { self.entries.lock().unwrap().push(e); }
    pub fn list(&self) -> Vec<MndpEntry> { self.entries.lock().unwrap().clone() }
}

impl Default for MndpManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mndp() {
        let m = MndpManager::new();
        m.add(MndpEntry { identity: "MikroTik-1".into(), version: "RouterOS 7.14".into(), platform: "MikroTik".into(), interface: "ether1".into(), address: "10.0.0.1".into(), mac: "00:11:22:33:44:55".into() });
        assert_eq!(m.list().len(), 1);
    }
}
