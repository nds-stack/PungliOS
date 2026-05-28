use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait DynamicRouting: Send + Sync {
    async fn add_bgp_peer(&self, peer: &BgpPeer) -> Result<()>;
    async fn remove_bgp_peer(&self, neighbor_ip: &str) -> Result<()>;
    async fn list_bgp_peers(&self) -> Result<Vec<BgpPeer>>;
    async fn get_bgp_status(&self) -> Result<BgpStatus>;
    async fn add_ospf_area(&self, area: &OspfArea) -> Result<()>;
    async fn remove_ospf_area(&self, area_id: &str) -> Result<()>;
    async fn list_ospf_areas(&self) -> Result<Vec<OspfArea>>;
    async fn get_ospf_status(&self) -> Result<OspfStatus>;
    async fn get_routing_table(
        &self,
        protocol: Option<RoutingProtocol>,
    ) -> Result<Vec<DynamicRoute>>;
}

#[derive(Clone, Default)]
pub struct MockDynamicRouting {
    peers: Arc<RwLock<HashMap<String, BgpPeer>>>,
    areas: Arc<RwLock<HashMap<String, OspfArea>>>,
    routes: Arc<RwLock<Vec<DynamicRoute>>>,
}

impl MockDynamicRouting {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DynamicRouting for MockDynamicRouting {
    async fn add_bgp_peer(&self, peer: &BgpPeer) -> Result<()> {
        let mut peers = self.peers.write().expect("lock poisoned");
        if peers.contains_key(&peer.neighbor_ip) {
            bail!("BGP peer '{}' already exists", peer.neighbor_ip);
        }
        peers.insert(peer.neighbor_ip.clone(), peer.clone());
        Ok(())
    }

    async fn remove_bgp_peer(&self, neighbor_ip: &str) -> Result<()> {
        let mut peers = self.peers.write().expect("lock poisoned");
        if peers.remove(neighbor_ip).is_none() {
            bail!("BGP peer '{neighbor_ip}' not found");
        }
        Ok(())
    }

    async fn list_bgp_peers(&self) -> Result<Vec<BgpPeer>> {
        let peers = self.peers.read().expect("lock poisoned");
        Ok(peers.values().cloned().collect())
    }

    async fn get_bgp_status(&self) -> Result<BgpStatus> {
        let peers = self.peers.read().expect("lock poisoned");
        let up = peers.values().filter(|p| p.enabled).count();
        Ok(BgpStatus {
            peers_count: peers.len(),
            up_peers: up,
            prefixes_received: 0,
            router_id: "10.0.0.1".into(),
            uptime_secs: 3600,
            local_asn: 64513,
        })
    }

    async fn add_ospf_area(&self, area: &OspfArea) -> Result<()> {
        let mut areas = self.areas.write().expect("lock poisoned");
        if areas.contains_key(&area.area_id) {
            bail!("OSPF area '{}' already exists", area.area_id);
        }
        areas.insert(area.area_id.clone(), area.clone());
        Ok(())
    }

    async fn remove_ospf_area(&self, area_id: &str) -> Result<()> {
        let mut areas = self.areas.write().expect("lock poisoned");
        if areas.remove(area_id).is_none() {
            bail!("OSPF area '{area_id}' not found");
        }
        Ok(())
    }

    async fn list_ospf_areas(&self) -> Result<Vec<OspfArea>> {
        let areas = self.areas.read().expect("lock poisoned");
        Ok(areas.values().cloned().collect())
    }

    async fn get_ospf_status(&self) -> Result<OspfStatus> {
        let areas = self.areas.read().expect("lock poisoned");
        Ok(OspfStatus {
            areas_count: areas.len(),
            neighbors_count: 0,
            router_id: "10.0.0.1".into(),
            uptime_secs: 3600,
            spf_runs: 42,
        })
    }

    async fn get_routing_table(
        &self,
        _protocol: Option<RoutingProtocol>,
    ) -> Result<Vec<DynamicRoute>> {
        let routes = self.routes.read().expect("lock poisoned");
        Ok(routes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_list_bgp_peer() {
        let backend = MockDynamicRouting::new();
        let peer = BgpPeer {
            neighbor_ip: "10.0.0.1".into(),
            remote_asn: 64512,
            local_asn: 64513,
            multihop: false,
            password: None,
            enabled: true,
            description: None,
        };
        backend.add_bgp_peer(&peer).await.unwrap();
        let peers = backend.list_bgp_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].neighbor_ip, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_add_duplicate_peer() {
        let backend = MockDynamicRouting::new();
        let peer = BgpPeer {
            neighbor_ip: "10.0.0.1".into(),
            remote_asn: 64512,
            local_asn: 64513,
            multihop: false,
            password: None,
            enabled: true,
            description: None,
        };
        backend.add_bgp_peer(&peer).await.unwrap();
        assert!(backend.add_bgp_peer(&peer).await.is_err());
    }

    #[tokio::test]
    async fn test_remove_bgp_peer() {
        let backend = MockDynamicRouting::new();
        let peer = BgpPeer {
            neighbor_ip: "10.0.0.1".into(),
            remote_asn: 64512,
            local_asn: 64513,
            multihop: false,
            password: None,
            enabled: true,
            description: None,
        };
        backend.add_bgp_peer(&peer).await.unwrap();
        backend.remove_bgp_peer("10.0.0.1").await.unwrap();
        assert!(backend.list_bgp_peers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_add_list_ospf_area() {
        let backend = MockDynamicRouting::new();
        let area = OspfArea {
            area_id: "0.0.0.0".into(),
            interfaces: vec!["eth0".into()],
            networks: vec!["10.0.0.0/24".into()],
            enabled: true,
        };
        backend.add_ospf_area(&area).await.unwrap();
        let areas = backend.list_ospf_areas().await.unwrap();
        assert_eq!(areas.len(), 1);
    }

    #[tokio::test]
    async fn test_bgp_status() {
        let backend = MockDynamicRouting::new();
        let peer = BgpPeer {
            neighbor_ip: "10.0.0.1".into(),
            remote_asn: 64512,
            local_asn: 64513,
            multihop: false,
            password: None,
            enabled: true,
            description: None,
        };
        backend.add_bgp_peer(&peer).await.unwrap();
        let status = backend.get_bgp_status().await.unwrap();
        assert_eq!(status.peers_count, 1);
        assert_eq!(status.up_peers, 1);
    }
}
