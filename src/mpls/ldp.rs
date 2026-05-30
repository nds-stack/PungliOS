use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MplsInterface {
    pub name: String,
    pub transport_address: String,
    pub enabled: bool,
    pub label_space: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspEntry {
    pub destination: String,
    pub label_in: u32,
    pub label_out: u32,
    pub nexthop: String,
    pub interface: String,
}

#[derive(Debug)]
pub struct MplsManager {
    interfaces: Mutex<HashMap<String, MplsInterface>>,
    lsps: Mutex<Vec<LspEntry>>,
}

impl Clone for MplsManager {
    fn clone(&self) -> Self {
        Self {
            interfaces: Mutex::new(self.interfaces.lock().unwrap().clone()),
            lsps: Mutex::new(self.lsps.lock().unwrap().clone()),
        }
    }
}

impl MplsManager {
    pub fn new() -> Self { Self { interfaces: Mutex::new(HashMap::new()), lsps: Mutex::new(Vec::new()) } }
    pub fn add_interface(&self, iface: MplsInterface) { self.interfaces.lock().unwrap().insert(iface.name.clone(), iface); }
    pub fn remove_interface(&self, name: &str) { self.interfaces.lock().unwrap().remove(name); }
    pub fn list_interfaces(&self) -> Vec<MplsInterface> { self.interfaces.lock().unwrap().values().cloned().collect() }
    pub fn add_lsp(&self, lsp: LspEntry) { self.lsps.lock().unwrap().push(lsp); }
    pub fn list_lsps(&self) -> Vec<LspEntry> { self.lsps.lock().unwrap().clone() }
}

impl Default for MplsManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mpls() {
        let mgr = MplsManager::new();
        mgr.add_interface(MplsInterface { name: "eth0".into(), transport_address: "10.0.0.1".into(), enabled: true, label_space: 0 });
        assert_eq!(mgr.list_interfaces().len(), 1);
        mgr.add_lsp(LspEntry { destination: "10.0.0.0/24".into(), label_in: 100, label_out: 200, nexthop: "10.0.0.2".into(), interface: "eth0".into() });
        assert_eq!(mgr.list_lsps().len(), 1);
    }
}
