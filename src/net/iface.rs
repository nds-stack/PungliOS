use crate::traits::{Interface, InterfaceConfig, NetlinkIfaces};
use anyhow::{Result, bail};
use std::fmt;

pub struct InterfaceManager<T: NetlinkIfaces> {
    backend: T,
}

impl<T: NetlinkIfaces + fmt::Debug> fmt::Debug for InterfaceManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceManager")
            .field("backend", &self.backend)
            .finish()
    }
}

impl<T: NetlinkIfaces> InterfaceManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn list(&self) -> Result<Vec<Interface>> {
        self.backend.list().await
    }

    pub async fn get(&self, name: &str) -> Result<Interface> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.get(name).await
    }

    pub async fn create(&self, config: &InterfaceConfig) -> Result<Interface> {
        if config.name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.create(config).await
    }

    pub async fn delete(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.delete(name).await
    }

    pub async fn set_up(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.set_up(name).await
    }

    pub async fn set_down(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.set_down(name).await
    }

    pub async fn set_mtu(&self, name: &str, mtu: u16) -> Result<()> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        if mtu < 68 {
            bail!("MTU must be at least 68");
        }
        if mtu > 9000 {
            bail!("MTU cannot exceed 9000 (jumbo frame limit)");
        }
        self.backend.set_mtu(name, mtu).await
    }

    pub async fn add_address(&self, name: &str, addr: std::net::IpAddr) -> Result<()> {
        if name.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.add_address(name, addr).await
    }

    pub async fn create_vlan(&self, parent: &str, vlan_id: u16) -> Result<Interface> {
        if parent.is_empty() {
            bail!("parent interface name cannot be empty");
        }
        if !(1..=4094).contains(&vlan_id) {
            bail!("VLAN ID must be between 1 and 4094, got {vlan_id}");
        }
        let name = format!("{parent}.{vlan_id}");
        let config = InterfaceConfig {
            name,
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: Some(vlan_id),
            bridge: None,
        };
        self.backend.create(&config).await
    }

    pub async fn add_to_bridge(&self, iface: &str, bridge: &str) -> Result<Interface> {
        if iface.is_empty() || bridge.is_empty() {
            bail!("interface and bridge names cannot be empty");
        }
        let config = InterfaceConfig {
            name: iface.to_string(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: Some(bridge.to_string()),
        };
        self.backend.create(&config).await
    }

    pub async fn remove_from_bridge(&self, iface: &str) -> Result<Interface> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let config = InterfaceConfig {
            name: iface.to_string(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        self.backend.create(&config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBackend;

    fn setup() -> InterfaceManager<MockBackend> {
        InterfaceManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_list_empty() {
        let mgr = setup();
        let list = mgr.list().await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn test_create_and_list() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: Some(1500),
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        let iface = mgr.create(&config).await.unwrap();
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.mtu, 1500);

        let list = mgr.list().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let mgr = setup();
        let err = mgr.get("nonexistent").await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_delete_interface() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        mgr.delete("eth0").await.unwrap();
        assert!(mgr.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_set_up_down() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        mgr.set_down("eth0").await.unwrap();
        let iface = mgr.get("eth0").await.unwrap();
        assert!(!iface.up);
        mgr.set_up("eth0").await.unwrap();
        let iface = mgr.get("eth0").await.unwrap();
        assert!(iface.up);
    }

    #[tokio::test]
    async fn test_set_mtu() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        mgr.set_mtu("eth0", 9000).await.unwrap();
        let iface = mgr.get("eth0").await.unwrap();
        assert_eq!(iface.mtu, 9000);
    }

    #[tokio::test]
    async fn test_set_mtu_too_low() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        let err = mgr.set_mtu("eth0", 10).await.unwrap_err();
        assert!(err.to_string().contains("at least 68"));
    }

    #[tokio::test]
    async fn test_create_vlan() {
        let mgr = setup();
        let iface = mgr.create_vlan("eth0", 100).await.unwrap();
        assert_eq!(iface.name, "eth0.100");
    }

    #[tokio::test]
    async fn test_create_vlan_invalid_id() {
        let mgr = setup();
        let err = mgr.create_vlan("eth0", 0).await.unwrap_err();
        assert!(err.to_string().contains("between 1 and 4094"));
        let err = mgr.create_vlan("eth0", 4095).await.unwrap_err();
        assert!(err.to_string().contains("between 1 and 4094"));
    }

    #[tokio::test]
    async fn test_add_to_bridge() {
        let mgr = setup();
        mgr.create_vlan("eth0", 100).await.unwrap();
        let iface = mgr.add_to_bridge("eth0.100", "br-lan").await.unwrap();
        assert_eq!(iface.name, "eth0.100");
    }

    #[tokio::test]
    async fn test_remove_from_bridge() {
        let mgr = setup();
        mgr.add_to_bridge("eth0", "br-lan").await.unwrap();
        let iface = mgr.remove_from_bridge("eth0").await.unwrap();
        assert_eq!(iface.name, "eth0");
    }

    #[tokio::test]
    async fn test_empty_name_rejected() {
        let mgr = setup();
        assert!(
            mgr.get("")
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot be empty")
        );
        assert!(
            mgr.delete("")
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot be empty")
        );
        assert!(
            mgr.set_up("")
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot be empty")
        );
        assert!(
            mgr.set_down("")
                .await
                .unwrap_err()
                .to_string()
                .contains("cannot be empty")
        );
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth1".into(),
            kind: None,
            mtu: Some(9000),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        let iface = mgr.get("eth1").await.unwrap();
        assert_eq!(iface.mtu, 9000);
        assert!(!iface.addresses.is_empty());
    }

    #[tokio::test]
    async fn test_add_address() {
        let mgr = setup();
        let config = InterfaceConfig {
            name: "eth0".into(),
            kind: None,
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        };
        mgr.create(&config).await.unwrap();
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        mgr.add_address("eth0", addr).await.unwrap();
        let iface = mgr.get("eth0").await.unwrap();
        assert!(iface.addresses.contains(&addr));
    }
}
