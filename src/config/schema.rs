use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceDef {
    pub name: String,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub addresses: Vec<String>,
    pub vlan_id: Option<u16>,
    pub bridge: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallZoneDef {
    pub name: String,
    #[serde(default)]
    pub interfaces: Vec<String>,
    pub forward: Option<String>,
    pub input: Option<String>,
    pub output: Option<String>,
    #[serde(default)]
    pub rules: Vec<FirewallRuleDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleDef {
    pub chain: String,
    pub protocol: Option<String>,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QdiscDef {
    pub kind: String,
    pub iface: String,
    pub handle: u32,
    pub parent: u32,
    pub rate: Option<u64>,
    pub ceil: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassDef {
    pub iface: String,
    pub classid: u32,
    pub parent: u32,
    pub rate: u64,
    pub ceil: u64,
    pub burst: Option<u64>,
    pub cburst: Option<u64>,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

fn default_priority() -> u8 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleDef {
    pub iface: String,
    pub kind: String,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub to_addr: Option<String>,
    pub to_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDef {
    pub destination: String,
    pub prefix: u8,
    pub nexthop: Option<String>,
    pub iface: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConntrackDef {
    #[serde(default = "default_conntrack_max")]
    pub max: u32,
    #[serde(default = "default_conntrack_buckets")]
    pub buckets: u32,
}

fn default_conntrack_max() -> u32 {
    262_144
}

fn default_conntrack_buckets() -> u32 {
    65_536
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub interfaces: Vec<InterfaceDef>,
    #[serde(default)]
    pub zones: Vec<FirewallZoneDef>,
    #[serde(default)]
    pub qdiscs: Vec<QdiscDef>,
    #[serde(default)]
    pub classes: Vec<ClassDef>,
    #[serde(default)]
    pub nat: Vec<NatRuleDef>,
    #[serde(default)]
    pub routes: Vec<RouteDef>,
    #[serde(default)]
    pub conntrack: ConntrackDef,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![],
            zones: vec![],
            qdiscs: vec![],
            classes: vec![],
            nat: vec![],
            routes: vec![],
            conntrack: ConntrackDef {
                max: default_conntrack_max(),
                buckets: default_conntrack_buckets(),
            },
        }
    }
}
