use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dot1xPort {
    pub name: String,
    pub enabled: bool,
    pub auth_type: String,
    pub timeout_secs: u32,
}

pub struct Dot1xManager { ports: Mutex<HashMap<String, Dot1xPort>> }

impl Dot1xManager {
    pub fn new() -> Self { Self { ports: Mutex::new(HashMap::new()) } }
    pub fn set_port(&self, port: Dot1xPort) { self.ports.lock().unwrap().insert(port.name.clone(), port); }
    pub fn remove_port(&self, name: &str) { self.ports.lock().unwrap().remove(name); }
    pub fn list_ports(&self) -> Vec<Dot1xPort> { self.ports.lock().unwrap().values().cloned().collect() }
}

impl Default for Dot1xManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dot1x() {
        let mgr = Dot1xManager::new();
        mgr.set_port(Dot1xPort { name: "eth0".into(), enabled: true, auth_type: "mac-auth-bypass".into(), timeout_secs: 30 });
        assert_eq!(mgr.list_ports().len(), 1);
    }
}
