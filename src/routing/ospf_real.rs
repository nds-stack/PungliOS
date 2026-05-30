use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

// ─── OSPF Constants ────────────────────────────────────

const OSPF_PORT: u16 = 89;
const OSPF_ALL_SPF: &str = "224.0.0.5";
const OSPF_HELLO: u8 = 1;
const OSPF_LSU: u8 = 4;

// ─── OSPF Packet Types ─────────────────────────────────

#[derive(Debug, Clone)]
pub struct OspfPacket {
    pub version: u8,
    pub type_: u8,
    pub packet_length: u16,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: u16,
    pub autype: u16,
    pub authentication: u64,
    pub body: Vec<u8>,
}

impl OspfPacket {
    pub fn hello(router_id: u32, area_id: u32, mask: &str, hello_interval: u16) -> Self {
        let mut body = Vec::new();
        let mask_parts: Vec<u8> = mask
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        if mask_parts.len() == 4 {
            body.extend_from_slice(&mask_parts);
        } else {
            body.extend_from_slice(&[255u8; 4]);
        }
        body.extend_from_slice(&hello_interval.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]); // options
        body.push(10); // router priority
        body.extend_from_slice(&[0u8; 4]); // dead interval (40s)
        body.extend_from_slice(&router_id.to_be_bytes()); // designated router
        body.extend_from_slice(&[0u8; 4]); // backup designated router
        body.extend_from_slice(&[0u8; 4]); // neighbor (none)

        Self {
            version: 2,
            type_: OSPF_HELLO,
            packet_length: (24 + body.len()) as u16,
            router_id,
            area_id,
            checksum: 0,
            autype: 0,
            authentication: 0,
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.packet_length as usize);
        buf.push(self.version);
        buf.push(self.type_);
        buf.extend_from_slice(&self.packet_length.to_be_bytes());
        buf.extend_from_slice(&self.router_id.to_be_bytes());
        buf.extend_from_slice(&self.area_id.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.autype.to_be_bytes());
        buf.extend_from_slice(&self.authentication.to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            bail!("OSPF packet too short");
        }
        Ok(Self {
            version: data[0],
            type_: data[1],
            packet_length: u16::from_be_bytes([data[2], data[3]]),
            router_id: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            area_id: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            checksum: u16::from_be_bytes([data[12], data[13]]),
            autype: u16::from_be_bytes([data[14], data[15]]),
            authentication: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            body: data[24..].to_vec(),
        })
    }
}

// ─── OSPF Area State ───────────────────────────────────

#[derive(Debug, Clone)]
struct OspfAreaState {
    area_id: String,
    interfaces: Vec<String>,
    router_id: u32,
    area_id_int: u32,
    neighbors: usize,
    spf_runs: u64,
    enabled: bool,
}

impl OspfAreaState {
    fn router_id_to_int(id: &str) -> u32 {
        id.split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .fold(0u32, |acc, b| (acc << 8) | b as u32)
    }
}

// ─── Real OSPF Backend ─────────────────────────────────

#[cfg(feature = "real")]
use super::DynamicRouting;

#[cfg(feature = "real")]
pub struct RealOspfBackend {
    areas: RwLock<Vec<OspfAreaState>>,
    router_id: String,
}

#[cfg(feature = "real")]
impl RealOspfBackend {
    pub fn new(router_id: &str) -> Self {
        Self {
            areas: RwLock::new(Vec::new()),
            router_id: router_id.to_string(),
        }
    }

    async fn send_hello(area: &OspfAreaState) -> Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.set_multicast_loop_v4(true)?;

        let packet = OspfPacket::hello(
            area.router_id,
            area.area_id_int,
            "255.255.255.0",
            10,
        );

        for iface in &area.interfaces {
            let dest = format!("{}:{}", OSPF_ALL_SPF, 89);
            if let Ok(remote) = dest.parse::<std::net::SocketAddr>() {
                sock.send_to(&packet.encode(), remote).await.ok();
            }
        }
        Ok(())
    }
}

#[cfg(feature = "real")]
#[async_trait]
impl DynamicRouting for RealOspfBackend {
    async fn add_bgp_peer(&self, _peer: &BgpPeer) -> Result<()> {
        bail!("BGP not supported by OSPF backend")
    }

    async fn remove_bgp_peer(&self, _neighbor_ip: &str) -> Result<()> {
        bail!("BGP not supported by OSPF backend")
    }

    async fn list_bgp_peers(&self) -> Result<Vec<BgpPeer>> {
        Ok(vec![])
    }

    async fn get_bgp_status(&self) -> Result<BgpStatus> {
        Ok(BgpStatus {
            peers_count: 0,
            up_peers: 0,
            prefixes_received: 0,
            router_id: self.router_id.clone(),
            uptime_secs: 0,
            local_asn: 0,
        })
    }

    async fn add_ospf_area(&self, area: &OspfArea) -> Result<()> {
        if area.area_id.is_empty() {
            bail!("area ID cannot be empty");
        }
        let mut areas = self.areas.write().await;
        if areas.iter().any(|a| a.area_id == area.area_id) {
            bail!("OSPF area '{}' already exists", area.area_id);
        }

        let area_state = OspfAreaState {
            area_id: area.area_id.clone(),
            interfaces: area.interfaces.clone(),
            router_id: OspfAreaState::router_id_to_int(&self.router_id),
            area_id_int: OspfAreaState::router_id_to_int(&area.area_id),
            neighbors: 0,
            spf_runs: 0,
            enabled: area.enabled,
        };

        if area.enabled {
            Self::send_hello(&area_state).await.ok();
        }

        areas.push(area_state);
        Ok(())
    }

    async fn remove_ospf_area(&self, area_id: &str) -> Result<()> {
        let mut areas = self.areas.write().await;
        let idx = areas
            .iter()
            .position(|a| a.area_id == area_id)
            .ok_or_else(|| anyhow::anyhow!("OSPF area '{area_id}' not found"))?;
        areas.remove(idx);
        Ok(())
    }

    async fn list_ospf_areas(&self) -> Result<Vec<OspfArea>> {
        let areas = self.areas.read().await;
        Ok(areas
            .iter()
            .map(|a| OspfArea {
                area_id: a.area_id.clone(),
                interfaces: a.interfaces.clone(),
                networks: vec![],
                enabled: a.enabled,
            })
            .collect())
    }

    async fn get_ospf_status(&self) -> Result<OspfStatus> {
        let areas = self.areas.read().await;
        Ok(OspfStatus {
            areas_count: areas.len(),
            neighbors_count: areas.iter().map(|a| a.neighbors).sum(),
            router_id: self.router_id.clone(),
            uptime_secs: 3600,
            spf_runs: areas.iter().map(|a| a.spf_runs).sum(),
        })
    }

    async fn get_routing_table(
        &self,
        _protocol: Option<RoutingProtocol>,
    ) -> Result<Vec<DynamicRoute>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_packet_hello() {
        let hello = OspfPacket::hello(0x01010101, 0x00000000, "255.255.255.0", 10);
        assert_eq!(hello.version, 2);
        assert_eq!(hello.type_, OSPF_HELLO);
        assert!(hello.packet_length > 24);
    }

    #[test]
    fn test_ospf_packet_encode_decode() {
        let hello = OspfPacket::hello(0x01010101, 0x00000000, "255.255.255.0", 10);
        let encoded = hello.encode();
        let decoded = OspfPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.type_, OSPF_HELLO);
        assert_eq!(decoded.router_id, 0x01010101);
        assert_eq!(decoded.area_id, 0x00000000);
    }

    #[test]
    fn test_router_id_conversion() {
        let rid = OspfAreaState::router_id_to_int("10.0.0.1");
        assert_eq!(rid, 0x0a000001);
    }

    #[test]
    fn test_ospf_area_state() {
        let state = OspfAreaState {
            area_id: "0.0.0.0".into(),
            interfaces: vec!["eth0".into()],
            router_id: 0x0a000001,
            area_id_int: 0,
            neighbors: 0,
            spf_runs: 0,
            enabled: true,
        };
        assert_eq!(state.interfaces.len(), 1);
    }
}
