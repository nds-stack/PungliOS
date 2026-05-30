use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueBurst {
    pub name: String,
    pub interface: String,
    pub burst_rate: u64,
    pub burst_threshold: u64,
    pub burst_time_secs: u32,
    pub rate: u64,
    pub ceil: u64,
    pub enabled: bool,
}

pub struct BurstManager { configs: Mutex<Vec<QueueBurst>> }

impl BurstManager {
    pub fn new() -> Self { Self { configs: Mutex::new(Vec::new()) } }
    pub fn add(&self, b: QueueBurst) { self.configs.lock().unwrap().push(b); }
    pub fn remove(&self, idx: usize) { self.configs.lock().unwrap().remove(idx); }
    pub fn list(&self) -> Vec<QueueBurst> { self.configs.lock().unwrap().clone() }
}

impl Default for BurstManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_burst() {
        let m = BurstManager::new();
        m.add(QueueBurst { name: "burst-1".into(), interface: "wan0".into(), burst_rate: 100_000, burst_threshold: 50_000, burst_time_secs: 10, rate: 10_000, ceil: 50_000, enabled: true });
        assert_eq!(m.list().len(), 1);
    }
}
