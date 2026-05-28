pub mod backend;
pub mod types;

pub use backend::*;
pub use types::*;

use anyhow::Result;

pub struct DynamicRoutingManager<T: DynamicRouting> {
    backend: T,
}

impl<T: DynamicRouting> DynamicRoutingManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn add_bgp_peer(&self, peer: &BgpPeer) -> Result<()> {
        if peer.neighbor_ip.is_empty() {
            anyhow::bail!("neighbor IP cannot be empty");
        }
        if peer.remote_asn == 0 {
            anyhow::bail!("remote ASN must be non-zero");
        }
        self.backend.add_bgp_peer(peer).await
    }

    pub async fn remove_bgp_peer(&self, neighbor_ip: &str) -> Result<()> {
        if neighbor_ip.is_empty() {
            anyhow::bail!("neighbor IP cannot be empty");
        }
        self.backend.remove_bgp_peer(neighbor_ip).await
    }

    pub async fn list_bgp_peers(&self) -> Result<Vec<BgpPeer>> {
        self.backend.list_bgp_peers().await
    }

    pub async fn get_bgp_status(&self) -> Result<BgpStatus> {
        self.backend.get_bgp_status().await
    }

    pub async fn add_ospf_area(&self, area: &OspfArea) -> Result<()> {
        if area.area_id.is_empty() {
            anyhow::bail!("area ID cannot be empty");
        }
        self.backend.add_ospf_area(area).await
    }

    pub async fn remove_ospf_area(&self, area_id: &str) -> Result<()> {
        if area_id.is_empty() {
            anyhow::bail!("area ID cannot be empty");
        }
        self.backend.remove_ospf_area(area_id).await
    }

    pub async fn list_ospf_areas(&self) -> Result<Vec<OspfArea>> {
        self.backend.list_ospf_areas().await
    }

    pub async fn get_ospf_status(&self) -> Result<OspfStatus> {
        self.backend.get_ospf_status().await
    }

    pub async fn get_routing_table(
        &self,
        protocol: Option<RoutingProtocol>,
    ) -> Result<Vec<DynamicRoute>> {
        self.backend.get_routing_table(protocol).await
    }
}
