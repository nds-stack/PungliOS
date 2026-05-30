use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRadiusBinding {
    pub pool_name: String,
    pub server: String,
    pub secret: String,
    pub default_lease_time: u32,
    pub enabled: bool,
}

pub struct DhcpRadiusManager { bindings: Mutex<Vec<DhcpRadiusBinding>> }

impl DhcpRadiusManager {
    pub fn new() -> Self { Self { bindings: Mutex::new(Vec::new()) } }
    pub fn add(&self, b: DhcpRadiusBinding) { self.bindings.lock().unwrap().push(b); }
    pub fn remove(&self, idx: usize) { self.bindings.lock().unwrap().remove(idx); }
    pub fn list(&self) -> Vec<DhcpRadiusBinding> { self.bindings.lock().unwrap().clone() }
}

impl Default for DhcpRadiusManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dhcp_radius() {
        let m = DhcpRadiusManager::new();
        m.add(DhcpRadiusBinding { pool_name: "pool1".into(), server: "10.0.0.1".into(), secret: "testing123".into(), default_lease_time: 3600, enabled: true });
        assert_eq!(m.list().len(), 1);
    }
}
