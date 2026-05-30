use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlanFilterMode {
    Access,
    Trunk,
}

impl std::fmt::Display for VlanFilterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Access => write!(f, "access"),
            Self::Trunk => write!(f, "trunk"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeVlanEntry {
    pub bridge: String,
    pub port: String,
    pub mode: VlanFilterMode,
    pub vlan_id: u16,
    pub tagged: bool,
    pub pvid: bool,
    pub untagged_vlans: Vec<u16>,
    pub tagged_vlans: Vec<u16>,
}

impl BridgeVlanEntry {
    pub fn is_member(&self, vlan: u16) -> bool {
        self.untagged_vlans.contains(&vlan) || self.tagged_vlans.contains(&vlan)
    }
}

pub struct BridgeVlanManager {
    entries: Mutex<Vec<BridgeVlanEntry>>,
}

impl BridgeVlanManager {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn add(&self, entry: BridgeVlanEntry) -> Result<()> {
        if entry.bridge.is_empty() {
            bail!("bridge name cannot be empty");
        }
        if entry.port.is_empty() {
            bail!("port name cannot be empty");
        }
        if entry.vlan_id < 1 || entry.vlan_id > 4094 {
            bail!("VLAN ID must be 1-4094");
        }

        let mut entries = self.entries.lock().unwrap();
        // Check for duplicate
        if entries
            .iter()
            .any(|e| e.bridge == entry.bridge && e.port == entry.port && e.vlan_id == entry.vlan_id)
        {
            bail!(
                "VLAN {vlan} already configured on {bridge}/{port}",
                vlan = entry.vlan_id,
                bridge = entry.bridge,
                port = entry.port
            );
        }
        entries.push(entry);
        Ok(())
    }

    pub fn remove(&self, bridge: &str, port: &str, vlan_id: u16) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        let len = entries.len();
        entries.retain(|e| !(e.bridge == bridge && e.port == port && e.vlan_id == vlan_id));
        if entries.len() == len {
            bail!("VLAN {vlan_id} not found on {bridge}/{port}");
        }
        Ok(())
    }

    pub fn list(&self, bridge: &str) -> Vec<BridgeVlanEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.bridge == bridge)
            .cloned()
            .collect()
    }

    pub fn list_all(&self) -> Vec<BridgeVlanEntry> {
        self.entries.lock().unwrap().clone()
    }

    pub fn list_bridges(&self) -> Vec<String> {
        let mut bridges: Vec<String> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.bridge.clone())
            .collect();
        bridges.sort();
        bridges.dedup();
        bridges
    }
}

impl Default for BridgeVlanManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_list() {
        let mgr = BridgeVlanManager::new();
        mgr.add(BridgeVlanEntry {
            bridge: "br0".into(),
            port: "eth0".into(),
            mode: VlanFilterMode::Trunk,
            vlan_id: 100,
            tagged: true,
            pvid: false,
            untagged_vlans: vec![],
            tagged_vlans: vec![100],
        })
        .unwrap();
        let entries = mgr.list("br0");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vlan_id, 100);
    }

    #[test]
    fn test_remove() {
        let mgr = BridgeVlanManager::new();
        mgr.add(BridgeVlanEntry {
            bridge: "br0".into(),
            port: "eth0".into(),
            mode: VlanFilterMode::Access,
            vlan_id: 10,
            tagged: false,
            pvid: true,
            untagged_vlans: vec![10],
            tagged_vlans: vec![],
        })
        .unwrap();
        mgr.remove("br0", "eth0", 10).unwrap();
        assert!(mgr.list("br0").is_empty());
    }

    #[test]
    fn test_invalid_vlan_rejected() {
        let mgr = BridgeVlanManager::new();
        assert!(mgr
            .add(BridgeVlanEntry {
                bridge: "br0".into(),
                port: "eth0".into(),
                mode: VlanFilterMode::Access,
                vlan_id: 0,
                tagged: false,
                pvid: true,
                untagged_vlans: vec![],
                tagged_vlans: vec![],
            })
            .is_err());
    }

    #[test]
    fn test_list_bridges() {
        let mgr = BridgeVlanManager::new();
        mgr.add(BridgeVlanEntry {
            bridge: "br0".into(),
            port: "eth0".into(),
            mode: VlanFilterMode::Trunk,
            vlan_id: 100,
            tagged: true,
            pvid: false,
            untagged_vlans: vec![],
            tagged_vlans: vec![100],
        })
        .unwrap();
        mgr.add(BridgeVlanEntry {
            bridge: "br1".into(),
            port: "eth1".into(),
            mode: VlanFilterMode::Access,
            vlan_id: 200,
            tagged: false,
            pvid: true,
            untagged_vlans: vec![200],
            tagged_vlans: vec![],
        })
        .unwrap();
        let bridges = mgr.list_bridges();
        assert_eq!(bridges.len(), 2);
    }

    #[test]
    fn test_member_check() {
        let entry = BridgeVlanEntry {
            bridge: "br0".into(),
            port: "eth0".into(),
            mode: VlanFilterMode::Trunk,
            vlan_id: 100,
            tagged: true,
            pvid: false,
            untagged_vlans: vec![],
            tagged_vlans: vec![100, 200],
        };
        assert!(entry.is_member(100));
        assert!(entry.is_member(200));
        assert!(!entry.is_member(300));
    }
}
