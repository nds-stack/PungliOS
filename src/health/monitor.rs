use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub temperature: f64,
    pub voltage: f64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub uptime_secs: u64,
}

pub struct HealthMonitor { status: Mutex<HealthStatus> }

impl HealthMonitor {
    pub fn new() -> Self { Self { status: Mutex::new(HealthStatus { temperature: 45.0, voltage: 12.0, cpu_usage: 15.0, memory_usage: 30.0, uptime_secs: 0 }) } }
    pub fn get_status(&self) -> HealthStatus { self.status.lock().unwrap().clone() }
    pub fn update(&self, s: HealthStatus) { *self.status.lock().unwrap() = s; }
}

impl Default for HealthMonitor { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_health() { let h = HealthMonitor::new(); assert!(h.get_status().temperature > 0.0); }
}
