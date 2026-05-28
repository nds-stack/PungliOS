use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait WireguardBackend: Send + Sync {
    async fn create_interface(&self, iface: &WireGuardInterface) -> Result<()>;
    async fn delete_interface(&self, name: &str) -> Result<()>;
    async fn list_interfaces(&self) -> Result<Vec<WireGuardInterface>>;
    async fn get_interface(&self, name: &str) -> Result<WireGuardInterface>;
    async fn add_peer(&self, peer: &WireGuardPeer) -> Result<()>;
    async fn remove_peer(&self, interface: &str, public_key: &str) -> Result<()>;
    async fn list_peers(&self, interface: &str) -> Result<Vec<WireGuardPeer>>;
    async fn get_status(&self) -> Result<WireGuardStatus>;
}

#[derive(Clone, Default)]
pub struct MockWireguardBackend {
    interfaces: Arc<RwLock<HashMap<String, WireGuardInterface>>>,
    peers: Arc<RwLock<Vec<WireGuardPeer>>>,
}

impl MockWireguardBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WireguardBackend for MockWireguardBackend {
    async fn create_interface(&self, iface: &WireGuardInterface) -> Result<()> {
        let mut interfaces = self.interfaces.write().expect("lock poisoned");
        if interfaces.contains_key(&iface.name) {
            bail!("WireGuard interface '{}' already exists", iface.name);
        }
        interfaces.insert(iface.name.clone(), iface.clone());
        Ok(())
    }

    async fn delete_interface(&self, name: &str) -> Result<()> {
        let mut interfaces = self.interfaces.write().expect("lock poisoned");
        if interfaces.remove(name).is_none() {
            bail!("WireGuard interface '{name}' not found");
        }
        let mut peers = self.peers.write().expect("lock poisoned");
        peers.retain(|p| p.interface != name);
        Ok(())
    }

    async fn list_interfaces(&self) -> Result<Vec<WireGuardInterface>> {
        let interfaces = self.interfaces.read().expect("lock poisoned");
        Ok(interfaces.values().cloned().collect())
    }

    async fn get_interface(&self, name: &str) -> Result<WireGuardInterface> {
        let interfaces = self.interfaces.read().expect("lock poisoned");
        interfaces
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("WireGuard interface '{name}' not found"))
    }

    async fn add_peer(&self, peer: &WireGuardPeer) -> Result<()> {
        let interfaces = self.interfaces.read().expect("lock poisoned");
        if !interfaces.contains_key(&peer.interface) {
            bail!("WireGuard interface '{}' not found", peer.interface);
        }
        let mut peers = self.peers.write().expect("lock poisoned");
        if peers
            .iter()
            .any(|p| p.interface == peer.interface && p.public_key == peer.public_key)
        {
            bail!(
                "peer '{}' already exists on interface '{}'",
                peer.public_key,
                peer.interface
            );
        }
        peers.push(peer.clone());
        Ok(())
    }

    async fn remove_peer(&self, interface: &str, public_key: &str) -> Result<()> {
        let mut peers = self.peers.write().expect("lock poisoned");
        let len = peers.len();
        peers.retain(|p| !(p.interface == interface && p.public_key == public_key));
        if peers.len() == len {
            bail!("peer '{public_key}' not found on interface '{interface}'");
        }
        Ok(())
    }

    async fn list_peers(&self, interface: &str) -> Result<Vec<WireGuardPeer>> {
        let peers = self.peers.read().expect("lock poisoned");
        Ok(peers
            .iter()
            .filter(|p| p.interface == interface)
            .cloned()
            .collect())
    }

    async fn get_status(&self) -> Result<WireGuardStatus> {
        let interfaces = self.interfaces.read().expect("lock poisoned");
        let peers = self.peers.read().expect("lock poisoned");
        Ok(WireGuardStatus {
            interfaces_count: interfaces.len(),
            total_peers: peers.len(),
            enabled_interfaces: interfaces.values().filter(|i| i.enabled).count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_iface(name: &str) -> WireGuardInterface {
        WireGuardInterface {
            name: name.into(),
            private_key: Some("cFYxQS6OSX4Y3hkfo+rJKfjHJGEXzr3hBmSto7vCH1w=".into()),
            listen_port: 51820,
            public_key: "xTU4Q6VUn/9JlRZ5UpnWmFXxUj/W0M6tRul0P73WMj4=".into(),
            enabled: true,
            mtu: 1420,
        }
    }

    fn test_peer(iface: &str) -> WireGuardPeer {
        WireGuardPeer {
            interface: iface.into(),
            public_key: "2BHWqL0y6c5zC1Jk4N7uR9vXpZwQ3m8nA5bDgFtEoWs=".into(),
            allowed_ips: vec!["10.0.0.2/32".into()],
            endpoint: Some("10.0.0.2".into()),
            endpoint_port: Some(51820),
            persistent_keepalive: Some(25),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_create_list_interface() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        let list = backend.list_interfaces().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_create_duplicate_interface() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        assert!(backend.create_interface(&test_iface("wg0")).await.is_err());
    }

    #[tokio::test]
    async fn test_delete_interface() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        backend.delete_interface("wg0").await.unwrap();
        assert!(backend.list_interfaces().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_add_list_peer() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        backend.add_peer(&test_peer("wg0")).await.unwrap();
        let peers = backend.list_peers("wg0").await.unwrap();
        assert_eq!(peers.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        let peer = test_peer("wg0");
        let pk = peer.public_key.clone();
        backend.add_peer(&peer).await.unwrap();
        backend.remove_peer("wg0", &pk).await.unwrap();
        assert!(backend.list_peers("wg0").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_status() {
        let backend = MockWireguardBackend::new();
        backend.create_interface(&test_iface("wg0")).await.unwrap();
        let status = backend.get_status().await.unwrap();
        assert_eq!(status.interfaces_count, 1);
    }
}
