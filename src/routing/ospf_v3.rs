use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ospfv3Area {
    pub area_id: String,
    pub interfaces: Vec<String>,
    pub enabled: bool,
    pub instance_id: u8,
}

pub struct Ospfv3Manager { areas: Mutex<HashMap<String, Ospfv3Area>> }

impl Ospfv3Manager {
    pub fn new() -> Self { Self { areas: Mutex::new(HashMap::new()) } }
    pub fn add_area(&self, area: Ospfv3Area) { self.areas.lock().unwrap().insert(area.area_id.clone(), area); }
    pub fn remove_area(&self, id: &str) { self.areas.lock().unwrap().remove(id); }
    pub fn list_areas(&self) -> Vec<Ospfv3Area> { self.areas.lock().unwrap().values().cloned().collect() }
}

impl Default for Ospfv3Manager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ospfv3() {
        let mgr = Ospfv3Manager::new();
        mgr.add_area(Ospfv3Area { area_id: "0.0.0.0".into(), interfaces: vec!["eth0".into()], enabled: true, instance_id: 0 });
        assert_eq!(mgr.list_areas().len(), 1);
    }
}
