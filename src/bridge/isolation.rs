use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortIsolationRule {
    pub bridge: String,
    pub port: String,
    pub isolated: bool,
    pub forward_to: Vec<String>,
}

pub struct PortIsolation { rules: Mutex<Vec<PortIsolationRule>> }

impl PortIsolation {
    pub fn new() -> Self { Self { rules: Mutex::new(Vec::new()) } }
    pub fn set(&self, r: PortIsolationRule) { let mut rules = self.rules.lock().unwrap(); if let Some(e) = rules.iter_mut().find(|x| x.bridge == r.bridge && x.port == r.port) { *e = r; } else { rules.push(r); } }
    pub fn list(&self) -> Vec<PortIsolationRule> { self.rules.lock().unwrap().clone() }
}

impl Default for PortIsolation { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_isolation() {
        let i = PortIsolation::new();
        i.set(PortIsolationRule { bridge: "br0".into(), port: "eth0".into(), isolated: true, forward_to: vec![] });
        assert_eq!(i.list().len(), 1);
    }
}
