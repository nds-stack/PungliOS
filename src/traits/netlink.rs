use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;

// ─── Interfaces ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub addresses: Vec<IpAddr>,
    pub mtu: u16,
    pub up: bool,
}

#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    pub name: String,
    pub mtu: Option<u16>,
    pub addresses: Vec<IpAddr>,
    pub vlan_id: Option<u16>,
    pub bridge: Option<String>,
}

#[async_trait]
pub trait NetlinkIfaces: Send + Sync {
    async fn list(&self) -> Result<Vec<Interface>>;
    async fn get(&self, name: &str) -> Result<Interface>;
    async fn create(&self, config: &InterfaceConfig) -> Result<Interface>;
    async fn delete(&self, name: &str) -> Result<()>;
    async fn set_up(&self, name: &str) -> Result<()>;
    async fn set_down(&self, name: &str) -> Result<()>;
    async fn set_mtu(&self, name: &str, mtu: u16) -> Result<()>;
    async fn add_address(&self, name: &str, addr: IpAddr) -> Result<()>;
}

// ─── Firewall / nftables ──────────────────────────────

#[derive(Debug, Clone)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
    Jump(String),
}

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub handle: u64,
    pub zone: String,
    pub chain: String,
    pub protocol: Option<String>,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub action: FirewallAction,
    pub positions: u32,
}

#[derive(Debug, Clone)]
pub struct FirewallZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub forward: Option<FirewallAction>,
    pub input: Option<FirewallAction>,
    pub output: Option<FirewallAction>,
}

#[async_trait]
pub trait NetlinkFirewall: Send + Sync {
    async fn list_rules(&self, zone: &str) -> Result<Vec<FirewallRule>>;
    async fn add_rule(&self, rule: &FirewallRule) -> Result<u64>;
    async fn delete_rule(&self, handle: u64) -> Result<()>;
    async fn flush_rules(&self) -> Result<()>;
    async fn create_zone(&self, zone: &FirewallZone) -> Result<()>;
}

// ─── QoS / tc ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum QdiscKind {
    Htb,
    FqCodel,
    Cake,
}

#[derive(Debug, Clone)]
pub struct QdiscConfig {
    pub kind: QdiscKind,
    pub iface: String,
    pub handle: u32,
    pub parent: u32,
    pub rate: Option<u64>,
    pub ceil: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ClassConfig {
    pub iface: String,
    pub classid: u32,
    pub parent: u32,
    pub rate: u64,
    pub ceil: u64,
    pub burst: Option<u64>,
    pub cburst: Option<u64>,
    pub priority: u8,
}

#[async_trait]
pub trait NetlinkQos: Send + Sync {
    async fn add_qdisc(&self, config: &QdiscConfig) -> Result<()>;
    async fn delete_qdisc(&self, iface: &str, handle: u32) -> Result<()>;
    async fn add_class(&self, config: &ClassConfig) -> Result<()>;
    async fn delete_class(&self, iface: &str, classid: u32) -> Result<()>;
}

// ─── Connection Tracking ──────────────────────────────

#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    pub protocol: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub state: String,
    pub bytes: u64,
    pub packets: u64,
    pub timeout: u32,
}

#[async_trait]
pub trait NetlinkConntrack: Send + Sync {
    async fn count(&self) -> Result<usize>;
    async fn list(&self) -> Result<Vec<ConntrackEntry>>;
    async fn flush(&self) -> Result<()>;
    async fn set_max(&self, max: u32) -> Result<()>;
    async fn set_buckets(&self, buckets: u32) -> Result<()>;
}

// ─── NAT ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NatRule {
    pub handle: u64,
    pub iface: String,
    pub kind: NatKind,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub to_addr: Option<IpAddr>,
    pub to_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub enum NatKind {
    Snat,
    Dnat,
    Masquerade,
}

#[async_trait]
pub trait NetlinkNat: Send + Sync {
    async fn add_rule(&self, rule: &NatRule) -> Result<u64>;
    async fn delete_rule(&self, handle: u64) -> Result<()>;
    async fn list_rules(&self) -> Result<Vec<NatRule>>;
}

// ─── Routing ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    pub nexthop: Option<IpAddr>,
    pub iface: Option<String>,
    pub metric: Option<u32>,
}

#[async_trait]
pub trait NetlinkRoute: Send + Sync {
    async fn add_route(&self, route: &Route) -> Result<()>;
    async fn delete_route(&self, destination: IpAddr, prefix: u8) -> Result<()>;
    async fn list_routes(&self) -> Result<Vec<Route>>;
}
