use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub interface: String,
    pub chassis_id: String,
    pub port_id: String,
    pub system_name: String,
    pub system_description: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub ttl: u16,
    pub last_seen: u64,
    pub protocol: String,
}

pub struct LldpAgent { neighbors: Mutex<HashMap<String, NeighborEntry>> }

impl LldpAgent {
    pub fn new() -> Self { Self { neighbors: Mutex::new(HashMap::new()) } }
    pub fn add_neighbor(&self, neighbor: NeighborEntry) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut n = neighbor; n.last_seen = now;
        self.neighbors.lock().unwrap().insert(n.chassis_id.clone(), n);
    }
    pub fn remove_neighbor(&self, chassis_id: &str) {
        self.neighbors.lock().unwrap().remove(chassis_id);
    }
    pub fn list_neighbors(&self) -> Vec<NeighborEntry> {
        let mut list: Vec<_> = self.neighbors.lock().unwrap().values().cloned().collect();
        list.sort_by_key(|n| n.last_seen);
        list.reverse(); list
    }
    pub fn count(&self) -> usize { self.neighbors.lock().unwrap().len() }
}

impl Default for LldpAgent { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_neighbor_add() {
        let agent = LldpAgent::new();
        agent.add_neighbor(NeighborEntry {
            interface: "eth0".into(), chassis_id: "00:11:22:33:44:55".into(),
            port_id: "Fa0/1".into(), system_name: "Switch-1".into(),
            system_description: "MikroTik CRS326".into(),
            ip_addresses: vec!["10.0.0.1".into()],
            mac_address: "00:11:22:33:44:55".into(), ttl: 120,
            last_seen: 0, protocol: "LLDP".into(),
        });
        assert_eq!(agent.count(), 1);
    }
}
