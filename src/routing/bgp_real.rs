use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;

// ─── BGP Message Types ─────────────────────────────────

const BGP_OPEN: u8 = 1;
const BGP_UPDATE: u8 = 2;
const BGP_NOTIFICATION: u8 = 3;
const BGP_KEEPALIVE: u8 = 4;

#[derive(Debug, Clone, PartialEq)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl std::fmt::Display for BgpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Connect => write!(f, "Connect"),
            Self::Active => write!(f, "Active"),
            Self::OpenSent => write!(f, "OpenSent"),
            Self::OpenConfirm => write!(f, "OpenConfirm"),
            Self::Established => write!(f, "Established"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BgpMessage {
    pub marker: [u8; 16],
    pub length: u16,
    pub type_: u8,
    pub body: Vec<u8>,
}

impl BgpMessage {
    pub fn new(type_: u8, body: Vec<u8>) -> Self {
        Self {
            marker: [0xffu8; 16],
            length: 19 + body.len() as u16,
            type_,
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.length as usize);
        buf.extend_from_slice(&self.marker);
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.push(self.type_);
        buf.extend_from_slice(&self.body);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 19 {
            bail!("BGP message too short");
        }
        let length = u16::from_be_bytes([data[16], data[17]]);
        if data.len() < length as usize {
            bail!("truncated BGP message");
        }
        Ok(Self {
            marker: data[..16].try_into().unwrap(),
            length,
            type_: data[18],
            body: data[19..length as usize].to_vec(),
        })
    }

    pub fn keepalive() -> Self {
        Self::new(BGP_KEEPALIVE, vec![])
    }

    pub fn open(my_asn: u32, hold_time: u16, router_id: &str) -> Self {
        let rid: u32 = router_id
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .fold(0u32, |acc, b| (acc << 8) | b as u32);

        let mut body = Vec::new();
        body.extend_from_slice(&(4u8.to_be_bytes()));
        body.extend_from_slice(&my_asn.to_be_bytes());
        body.extend_from_slice(&hold_time.to_be_bytes());
        body.extend_from_slice(&rid.to_be_bytes());
        body.extend_from_slice(&[0u8; 2]);
        Self::new(BGP_OPEN, body)
    }

    pub fn encode_update(
        withdrawn_routes: &[String],
        path_attributes: &[(u8, Vec<u8>)],
        nlri: &[String],
    ) -> Self {
        let mut body = Vec::new();

        let wd_len: u16 = withdrawn_routes
            .iter()
            .map(|r| {
                let (prefix, len) = parse_cidr(r);
                (len as u16 + 1) / 8 + 1
            })
            .sum();
        body.extend_from_slice(&wd_len.to_be_bytes());

        for route in withdrawn_routes {
            let (prefix, len) = parse_cidr(route);
            let bytes = (len as f64 / 8.0).ceil() as usize;
            body.push(len);
            match prefix {
                IpAddr::V4(ip) => body.extend_from_slice(&ip.octets()[..bytes]),
                IpAddr::V6(ip) => body.extend_from_slice(&ip.octets()[..bytes]),
            }
        }

        let mut attr_bytes = Vec::new();
        for (flag, attr_data) in path_attributes {
            let a_len = attr_data.len() as u16;
            attr_bytes.push(*flag);
            attr_bytes.push(*flag | 0x10);
            attr_bytes.extend_from_slice(&a_len.to_be_bytes());
            attr_bytes.extend_from_slice(attr_data);
        }
        body.extend_from_slice(&(attr_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&attr_bytes);

        for route in nlri {
            let (prefix, len) = parse_cidr(route);
            let bytes = (len as f64 / 8.0).ceil() as usize;
            body.push(len);
            match prefix {
                IpAddr::V4(ip) => body.extend_from_slice(&ip.octets()[..bytes]),
                IpAddr::V6(ip) => body.extend_from_slice(&ip.octets()[..bytes]),
            }
        }

        Self::new(BGP_UPDATE, body)
    }
}

fn parse_cidr(s: &str) -> (IpAddr, u8) {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() == 2 {
        let ip: IpAddr = parts[0].parse().unwrap_or("0.0.0.0".parse().unwrap());
        let len: u8 = parts[1].parse().unwrap_or(32);
        (ip, len)
    } else {
        ("0.0.0.0".parse().unwrap(), 32)
    }
}

fn encode_as_path(as_path: &[u32]) -> Vec<u8> {
    let mut value = Vec::new();
    if as_path.len() <= 255 {
        value.push(0x02);
        value.push(as_path.len() as u8);
        for asn in as_path {
            value.extend_from_slice(&asn.to_be_bytes());
        }
    }
    let a_len = value.len() as u16;
    let mut attr = vec![0x40, a_len as u8];
    attr.extend_from_slice(&value);
    attr
}

fn encode_next_hop(nexthop: &IpAddr) -> Vec<u8> {
    let mut value = Vec::new();
    if let IpAddr::V4(ip) = nexthop {
        value.extend_from_slice(&ip.octets());
    }
    let a_len = value.len() as u16;
    let mut attr = vec![0x40, a_len as u8];
    attr.push(3);
    attr.extend_from_slice(&value);
    attr
}

fn encode_origin() -> Vec<u8> {
    vec![0x40, 0x01, 0x00]
}

struct BgpSession {
    neighbor_ip: String,
    remote_asn: u32,
    local_asn: u32,
    state: BgpState,
    prefixes_received: usize,
    uptime_secs: u64,
}

impl BgpSession {
    fn new(neighbor_ip: &str, remote_asn: u32, local_asn: u32) -> Self {
        Self {
            neighbor_ip: neighbor_ip.to_string(),
            remote_asn,
            local_asn,
            state: BgpState::Idle,
            prefixes_received: 0,
            uptime_secs: 0,
        }
    }
}

// ─── Real BGP Backend ───────────────────────────────────

#[cfg(feature = "real")]
use super::DynamicRouting;

#[cfg(feature = "real")]
pub struct RealBgpBackend {
    sessions: RwLock<HashMap<String, BgpSession>>,
    router_id: String,
    local_asn: u32,
}

#[cfg(feature = "real")]
impl RealBgpBackend {
    pub fn new(router_id: &str, local_asn: u32) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            router_id: router_id.to_string(),
            local_asn,
        }
    }

    async fn connect_peer(&self, peer: &BgpPeer) -> Result<BgpState> {
        let addr = format!("{}:179", peer.neighbor_ip);
        match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let open = BgpMessage::open(self.local_asn, 90, &self.router_id);
                let _ = stream
                    .try_write(&open.encode())
                    .map_err(|e| anyhow::anyhow!("send open failed: {e}"))?;

                let mut buf = [0u8; 4096];
                match timeout(Duration::from_secs(30), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 19 => {
                        let msg = BgpMessage::decode(&buf[..n])?;
                        if msg.type_ != BGP_OPEN {
                            bail!("expected OPEN, got type {}", msg.type_);
                        }
                    }
                    _ => return Ok(BgpState::Active),
                }

                let ka = BgpMessage::keepalive();
                let _ = stream.try_write(&ka.encode());

                match timeout(Duration::from_secs(30), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 19 => {
                        let msg = BgpMessage::decode(&buf[..n])?;
                        if msg.type_ == BGP_KEEPALIVE {
                            Ok(BgpState::Established)
                        } else if msg.type_ == BGP_NOTIFICATION {
                            Ok(BgpState::Idle)
                        } else {
                            Ok(BgpState::OpenConfirm)
                        }
                    }
                    _ => Ok(BgpState::Active),
                }
            }
            Ok(Err(_)) => Ok(BgpState::Active),
            Err(_) => Ok(BgpState::Active),
        }
    }
}

#[cfg(feature = "real")]
#[async_trait]
impl DynamicRouting for RealBgpBackend {
    async fn add_bgp_peer(&self, peer: &BgpPeer) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(&peer.neighbor_ip) {
            bail!("BGP peer '{}' already exists", peer.neighbor_ip);
        }

        let mut session =
            BgpSession::new(&peer.neighbor_ip, peer.remote_asn, self.local_asn);

        if peer.enabled {
            session.state = self.connect_peer(peer).await?;
            if session.state == BgpState::Established {
                session.uptime_secs = 0;
            }
        }

        sessions.insert(peer.neighbor_ip.clone(), session);
        Ok(())
    }

    async fn remove_bgp_peer(&self, neighbor_ip: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(neighbor_ip).is_none() {
            bail!("BGP peer '{neighbor_ip}' not found");
        }
        Ok(())
    }

    async fn list_bgp_peers(&self) -> Result<Vec<BgpPeer>> {
        let sessions = self.sessions.read().await;
        Ok(sessions
            .keys()
            .map(|ip| BgpPeer {
                neighbor_ip: ip.clone(),
                remote_asn: 0,
                local_asn: self.local_asn,
                multihop: false,
                password: None,
                enabled: true,
                description: None,
            })
            .collect())
    }

    async fn get_bgp_status(&self) -> Result<BgpStatus> {
        let sessions = self.sessions.read().await;
        let total = sessions.len();
        let up = sessions
            .values()
            .filter(|s| s.state == BgpState::Established)
            .count();
        let prefixes = sessions.values().map(|s| s.prefixes_received).sum();
        Ok(BgpStatus {
            peers_count: total,
            up_peers: up,
            prefixes_received: prefixes,
            router_id: self.router_id.clone(),
            uptime_secs: 3600,
            local_asn: self.local_asn,
        })
    }

    async fn add_ospf_area(&self, _area: &OspfArea) -> Result<()> {
        bail!("OSPF not supported by BGP backend")
    }

    async fn remove_ospf_area(&self, _area_id: &str) -> Result<()> {
        bail!("OSPF not supported by BGP backend")
    }

    async fn list_ospf_areas(&self) -> Result<Vec<OspfArea>> {
        Ok(vec![])
    }

    async fn get_ospf_status(&self) -> Result<OspfStatus> {
        Ok(OspfStatus {
            areas_count: 0,
            neighbors_count: 0,
            router_id: self.router_id.clone(),
            uptime_secs: 0,
            spf_runs: 0,
        })
    }

    async fn get_routing_table(
        &self,
        _protocol: Option<RoutingProtocol>,
    ) -> Result<Vec<DynamicRoute>> {
        Ok(vec![])
    }
}

#[cfg(not(feature = "real"))]
use super::backend::MockDynamicRouting;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_message_encode_decode() {
        let ka = BgpMessage::keepalive();
        let encoded = ka.encode();
        assert_eq!(encoded.len(), 19);
        assert_eq!(encoded[18], BGP_KEEPALIVE);

        let decoded = BgpMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.type_, BGP_KEEPALIVE);
        assert_eq!(decoded.length, 19);
    }

    #[test]
    fn test_open_message() {
        let open = BgpMessage::open(64513, 90, "10.0.0.1");
        assert_eq!(open.type_, BGP_OPEN);
        assert_eq!(open.length, 29);
    }

    #[test]
    fn test_update_message() {
        let update = BgpMessage::encode_update(
            &[],
            &[(0x40, encode_origin())],
            &["10.0.0.0/24".into()],
        );
        assert_eq!(update.type_, BGP_UPDATE);
    }

    #[test]
    fn test_bgp_state_display() {
        assert_eq!(BgpState::Idle.to_string(), "Idle");
        assert_eq!(BgpState::Established.to_string(), "Established");
    }

    #[test]
    fn test_as_path_encoding() {
        let encoded = encode_as_path(&[64512, 64513]);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_origin_encoding() {
        let origin = encode_origin();
        assert_eq!(origin.len(), 3);
    }

    #[test]
    fn test_next_hop_encoding() {
        let nh: IpAddr = "10.0.0.1".parse().unwrap();
        let encoded = encode_next_hop(&nh);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_bgp_session() {
        let session = BgpSession::new("10.0.0.1", 64512, 64513);
        assert_eq!(session.state, BgpState::Idle);
        assert_eq!(session.prefixes_received, 0);
    }
}
