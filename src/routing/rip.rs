use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipInterface {
    pub name: String,
    pub enabled: bool,
    pub send_version: u8,
    pub receive_version: u8,
    pub authentication: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RipRoute {
    pub destination: String,
    pub nexthop: String,
    pub metric: u8,
    pub tag: u16,
}

pub struct RipManager {
    interfaces: Mutex<HashMap<String, RipInterface>>,
    routes: Mutex<Vec<RipRoute>>,
}

impl RipManager {
    pub fn new() -> Self { Self { interfaces: Mutex::new(HashMap::new()), routes: Mutex::new(Vec::new()) } }
    pub fn add_interface(&self, iface: RipInterface) { self.interfaces.lock().unwrap().insert(iface.name.clone(), iface); }
    pub fn remove_interface(&self, name: &str) { self.interfaces.lock().unwrap().remove(name); }
    pub fn list_interfaces(&self) -> Vec<RipInterface> { self.interfaces.lock().unwrap().values().cloned().collect() }
    pub fn add_route(&self, route: RipRoute) { self.routes.lock().unwrap().push(route); }
    pub fn list_routes(&self) -> Vec<RipRoute> { self.routes.lock().unwrap().clone() }
}

impl Default for RipManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rip() {
        let mgr = RipManager::new();
        mgr.add_interface(RipInterface { name: "eth0".into(), enabled: true, send_version: 2, receive_version: 2, authentication: None });
        assert_eq!(mgr.list_interfaces().len(), 1);
    }
}
