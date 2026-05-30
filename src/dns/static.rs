use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStaticEntry {
    pub name: String,
    pub r#type: String,
    pub value: String,
    pub ttl: u32,
}

pub struct DnsStaticManager { entries: Mutex<HashMap<String, DnsStaticEntry>> }

impl DnsStaticManager {
    pub fn new() -> Self { Self { entries: Mutex::new(HashMap::new()) } }
    pub fn add(&self, entry: DnsStaticEntry) {
        self.entries.lock().unwrap().insert(entry.name.clone(), entry);
    }
    pub fn remove(&self, name: &str) { self.entries.lock().unwrap().remove(name); }
    pub fn list(&self) -> Vec<DnsStaticEntry> {
        self.entries.lock().unwrap().values().cloned().collect()
    }
    pub fn resolve(&self, name: &str) -> Option<String> {
        self.entries.lock().unwrap().get(name).map(|e| e.value.clone())
    }
}

impl Default for DnsStaticManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_static_dns() {
        let mgr = DnsStaticManager::new();
        mgr.add(DnsStaticEntry {
            name: "router.local".into(), r#type: "A".into(),
            value: "10.0.0.1".into(), ttl: 86400,
        });
        assert_eq!(mgr.resolve("router.local").unwrap(), "10.0.0.1");
    }
}
