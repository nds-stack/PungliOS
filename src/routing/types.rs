use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BgpPeer {
    pub neighbor_ip: String,
    pub remote_asn: u32,
    pub local_asn: u32,
    pub multihop: bool,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OspfArea {
    pub area_id: String,
    pub interfaces: Vec<String>,
    pub networks: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RoutingProtocol {
    Bgp,
    Ospf,
    Static,
    Connected,
}

#[derive(Debug, Clone, Serialize)]
pub struct DynamicRoute {
    pub destination: String,
    pub prefix: u8,
    pub nexthop: String,
    pub metric: u32,
    pub protocol: RoutingProtocol,
    pub age_secs: u64,
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BgpStatus {
    pub peers_count: usize,
    pub up_peers: usize,
    pub prefixes_received: usize,
    pub router_id: String,
    pub uptime_secs: u64,
    pub local_asn: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct OspfStatus {
    pub areas_count: usize,
    pub neighbors_count: usize,
    pub router_id: String,
    pub uptime_secs: u64,
    pub spf_runs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_peer_creation() {
        let peer = BgpPeer {
            neighbor_ip: "10.0.0.1".into(),
            remote_asn: 64512,
            local_asn: 64513,
            multihop: false,
            password: None,
            enabled: true,
            description: Some("upstream-1".into()),
        };
        assert_eq!(peer.remote_asn, 64512);
        assert_eq!(peer.neighbor_ip, "10.0.0.1");
    }

    #[test]
    fn test_ospf_area_creation() {
        let area = OspfArea {
            area_id: "0.0.0.0".into(),
            interfaces: vec!["eth0".into(), "eth1".into()],
            networks: vec!["10.0.0.0/24".into()],
            enabled: true,
        };
        assert_eq!(area.area_id, "0.0.0.0");
        assert_eq!(area.interfaces.len(), 2);
    }

    #[test]
    fn test_routing_protocol_display() {
        assert_eq!(format!("{:?}", RoutingProtocol::Bgp), "Bgp");
        assert_eq!(format!("{:?}", RoutingProtocol::Ospf), "Ospf");
    }
}
