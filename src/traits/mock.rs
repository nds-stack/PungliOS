use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use async_trait::async_trait;

use super::netlink::*;

// ─── MockBackend ──────────────────────────────────────

#[derive(Clone, Default)]
pub struct MockBackend {
    pub interfaces: Arc<RwLock<HashMap<String, Interface>>>,
    pub rules: Arc<RwLock<Vec<FirewallRule>>>,
    pub zones: Arc<RwLock<HashMap<String, FirewallZone>>>,
    pub classes: Arc<RwLock<Vec<ClassConfig>>>,
    pub conntrack: Arc<RwLock<Vec<ConntrackEntry>>>,
    pub nat_rules: Arc<RwLock<Vec<NatRule>>>,
    pub routes: Arc<RwLock<Vec<Route>>>,
    pub next_handle: Arc<RwLock<u64>>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_default_iface(&self, name: &str) {
        let iface = Interface {
            name: name.to_string(),
            index: 1,
            mac: [0x00; 6],
            addresses: vec![],
            mtu: 1500,
            up: true,
        };
        self.interfaces.write().unwrap().insert(name.to_string(), iface);
    }

    fn next_handle(&self) -> u64 {
        let mut h = self.next_handle.write().unwrap();
        *h += 1;
        *h
    }
}

// ─── NetlinkIfaces ────────────────────────────────────

#[async_trait]
impl NetlinkIfaces for MockBackend {
    async fn list(&self) -> Result<Vec<Interface>> {
        Ok(self.interfaces.read().unwrap().values().cloned().collect())
    }

    async fn get(&self, name: &str) -> Result<Interface> {
        self.interfaces
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("interface {name} not found"))
    }

    async fn create(&self, config: &InterfaceConfig) -> Result<Interface> {
        let iface = Interface {
            name: config.name.clone(),
            index: 1,
            mac: [0x00; 6],
            addresses: config.addresses.clone(),
            mtu: config.mtu.unwrap_or(1500),
            up: true,
        };
        self.interfaces.write().unwrap().insert(config.name.clone(), iface.clone());
        Ok(iface)
    }

    async fn delete(&self, name: &str) -> Result<()> {
        self.interfaces.write().unwrap().remove(name);
        Ok(())
    }

    async fn set_up(&self, name: &str) -> Result<()> {
        if let Some(iface) = self.interfaces.write().unwrap().get_mut(name) {
            iface.up = true;
        }
        Ok(())
    }

    async fn set_down(&self, name: &str) -> Result<()> {
        if let Some(iface) = self.interfaces.write().unwrap().get_mut(name) {
            iface.up = false;
        }
        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u16) -> Result<()> {
        if let Some(iface) = self.interfaces.write().unwrap().get_mut(name) {
            iface.mtu = mtu;
        }
        Ok(())
    }

    async fn add_address(&self, name: &str, addr: IpAddr) -> Result<()> {
        if let Some(iface) = self.interfaces.write().unwrap().get_mut(name) {
            iface.addresses.push(addr);
        }
        Ok(())
    }
}

// ─── NetlinkFirewall ──────────────────────────────────

#[async_trait]
impl NetlinkFirewall for MockBackend {
    async fn list_rules(&self, _zone: &str) -> Result<Vec<FirewallRule>> {
        Ok(self.rules.read().unwrap().clone())
    }

    async fn add_rule(&self, rule: &FirewallRule) -> Result<u64> {
        let mut rule = rule.clone();
        rule.handle = self.next_handle();
        let handle = rule.handle;
        self.rules.write().unwrap().push(rule);
        Ok(handle)
    }

    async fn delete_rule(&self, handle: u64) -> Result<()> {
        self.rules.write().unwrap().retain(|r| r.handle != handle);
        Ok(())
    }

    async fn flush_rules(&self) -> Result<()> {
        self.rules.write().unwrap().clear();
        Ok(())
    }

    async fn create_zone(&self, zone: &FirewallZone) -> Result<()> {
        self.zones.write().unwrap().insert(zone.name.clone(), zone.clone());
        Ok(())
    }
}

// ─── NetlinkQos ───────────────────────────────────────

#[async_trait]
impl NetlinkQos for MockBackend {
    async fn add_qdisc(&self, _config: &QdiscConfig) -> Result<()> {
        Ok(())
    }

    async fn delete_qdisc(&self, _iface: &str, _handle: u32) -> Result<()> {
        Ok(())
    }

    async fn add_class(&self, config: &ClassConfig) -> Result<()> {
        self.classes.write().unwrap().push(config.clone());
        Ok(())
    }

    async fn delete_class(&self, _iface: &str, classid: u32) -> Result<()> {
        self.classes.write().unwrap().retain(|c| c.classid != classid);
        Ok(())
    }
}

// ─── NetlinkConntrack ─────────────────────────────────

#[async_trait]
impl NetlinkConntrack for MockBackend {
    async fn count(&self) -> Result<usize> {
        Ok(self.conntrack.read().unwrap().len())
    }

    async fn list(&self) -> Result<Vec<ConntrackEntry>> {
        Ok(self.conntrack.read().unwrap().clone())
    }

    async fn flush(&self) -> Result<()> {
        self.conntrack.write().unwrap().clear();
        Ok(())
    }

    async fn set_max(&self, _max: u32) -> Result<()> {
        Ok(())
    }

    async fn set_buckets(&self, _buckets: u32) -> Result<()> {
        Ok(())
    }
}

// ─── NetlinkNat ───────────────────────────────────────

#[async_trait]
impl NetlinkNat for MockBackend {
    async fn add_rule(&self, rule: &NatRule) -> Result<u64> {
        let mut rule = rule.clone();
        rule.handle = self.next_handle();
        let handle = rule.handle;
        self.nat_rules.write().unwrap().push(rule);
        Ok(handle)
    }

    async fn delete_rule(&self, handle: u64) -> Result<()> {
        self.nat_rules.write().unwrap().retain(|r| r.handle != handle);
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<NatRule>> {
        Ok(self.nat_rules.read().unwrap().clone())
    }
}

// ─── NetlinkRoute ─────────────────────────────────────

#[async_trait]
impl NetlinkRoute for MockBackend {
    async fn add_route(&self, route: &Route) -> Result<()> {
        self.routes.write().unwrap().push(route.clone());
        Ok(())
    }

    async fn delete_route(&self, destination: IpAddr, prefix: u8) -> Result<()> {
        self.routes.write().unwrap().retain(|r| {
            r.destination != destination || r.prefix != prefix
        });
        Ok(())
    }

    async fn list_routes(&self) -> Result<Vec<Route>> {
        Ok(self.routes.read().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_interface() {
        let backend = MockBackend::new();
        let config = InterfaceConfig {
            name: "eth0".into(),
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        let iface = backend.create(&config).await.unwrap();
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.mtu, 1500);
    }

    #[tokio::test]
    async fn test_add_firewall_rule() {
        let backend = MockBackend::new();
        let rule = FirewallRule {
            handle: 0,
            zone: "lan".into(),
            chain: "forward".into(),
            protocol: Some("tcp".into()),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: Some(80),
            action: FirewallAction::Accept,
            positions: 0,
        };
        let handle = NetlinkFirewall::add_rule(&backend, &rule).await.unwrap();
        assert!(handle > 0);
        let rules = NetlinkFirewall::list_rules(&backend, "lan").await.unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_qos_class() {
        let backend = MockBackend::new();
        let class = ClassConfig {
            iface: "eth0".into(),
            classid: 1,
            parent: 0x10,
            rate: 10_000_000,
            ceil: 10_000_000,
            burst: None,
            cburst: None,
            priority: 3,
        };
        backend.add_class(&class).await.unwrap();
        assert_eq!(backend.classes.read().unwrap().len(), 1);
    }
}
