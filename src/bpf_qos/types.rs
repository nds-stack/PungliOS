use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BpfQdiscConfig {
    pub iface: String,
    pub kind: BpfQdiscKind,
    pub rate: u64,
    pub burst: Option<u64>,
    pub latency: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BpfQdiscKind {
    Fq,
    FqCodel,
    Cake,
    Edt,
}

#[derive(Debug, Clone, Serialize)]
pub struct EdtClass {
    pub iface: String,
    pub classid: String,
    pub rate: u64,
    pub burst: Option<u64>,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct BpfQosStatus {
    pub qdiscs_count: usize,
    pub classes_count: usize,
    pub active_interfaces: Vec<String>,
}
