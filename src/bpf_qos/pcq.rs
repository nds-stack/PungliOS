use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct PcqManager {
    classes: Mutex<HashMap<String, PcqClass>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcqClass {
    pub name: String,
    pub interface: String,
    pub rate: u64,
    pub ceil: u64,
    pub bucket_size: u32,
    pub hash_methods: Vec<PcqHashMethod>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcqHashMethod {
    SrcAddress,
    DstAddress,
    SrcPort,
    DstPort,
    BothAddresses,
}

impl std::fmt::Display for PcqHashMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SrcAddress => write!(f, "src-address"),
            Self::DstAddress => write!(f, "dst-address"),
            Self::SrcPort => write!(f, "src-port"),
            Self::DstPort => write!(f, "dst-port"),
            Self::BothAddresses => write!(f, "both-addresses"),
        }
    }
}

impl PcqManager {
    pub fn new() -> Self {
        Self {
            classes: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_class(&self, class: PcqClass) -> Result<()> {
        if class.name.is_empty() {
            bail!("PCQ class name cannot be empty");
        }
        let mut classes = self.classes.lock().unwrap();
        if classes.contains_key(&class.name) {
            bail!("PCQ class '{}' already exists", class.name);
        }
        classes.insert(class.name.clone(), class);
        Ok(())
    }

    pub fn remove_class(&self, name: &str) -> Result<()> {
        let mut classes = self.classes.lock().unwrap();
        classes
            .remove(name)
            .ok_or_else(|| anyhow::anyhow!("PCQ class '{name}' not found"))?;
        Ok(())
    }

    pub fn list_classes(&self) -> Vec<PcqClass> {
        self.classes
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    pub fn get_class(&self, name: &str) -> Option<PcqClass> {
        self.classes.lock().unwrap().get(name).cloned()
    }
}

impl Default for PcqManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_list_class() {
        let mgr = PcqManager::new();
        mgr.add_class(PcqClass {
            name: "pcq-upload".into(),
            interface: "wan0".into(),
            rate: 10_000,
            ceil: 100_000,
            bucket_size: 16,
            hash_methods: vec![PcqHashMethod::SrcAddress],
            enabled: true,
        })
        .unwrap();
        assert_eq!(mgr.list_classes().len(), 1);
    }

    #[test]
    fn test_remove_class() {
        let mgr = PcqManager::new();
        mgr.add_class(PcqClass {
            name: "test".into(),
            interface: "eth0".into(),
            rate: 1000,
            ceil: 10000,
            bucket_size: 16,
            hash_methods: vec![],
            enabled: true,
        })
        .unwrap();
        mgr.remove_class("test").unwrap();
        assert!(mgr.list_classes().is_empty());
    }

    #[test]
    fn test_hash_method_display() {
        assert_eq!(PcqHashMethod::BothAddresses.to_string(), "both-addresses");
    }
}
