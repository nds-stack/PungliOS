use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u64,
    pub packets: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub tcp_flags: Option<u8>,
}

pub struct FlowExporter {
    records: Mutex<Vec<FlowRecord>>,
    collectors: Mutex<Vec<String>>,
    enabled: Mutex<bool>,
}

impl FlowExporter {
    pub fn new() -> Self {
        Self { records: Mutex::new(Vec::new()), collectors: Mutex::new(Vec::new()), enabled: Mutex::new(false) }
    }
    pub fn set_enabled(&self, val: bool) { *self.enabled.lock().unwrap() = val; }
    pub fn is_enabled(&self) -> bool { *self.enabled.lock().unwrap() }
    pub fn add_collector(&self, addr: &str) { self.collectors.lock().unwrap().push(addr.to_string()); }
    pub fn list_collectors(&self) -> Vec<String> { self.collectors.lock().unwrap().clone() }
    pub fn add_record(&self, record: FlowRecord) {
        self.records.lock().unwrap().push(record);
    }
    pub fn get_records(&self) -> Vec<FlowRecord> { self.records.lock().unwrap().clone() }
    pub fn clear_records(&self) { self.records.lock().unwrap().clear(); }
}

impl Default for FlowExporter { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_flow() {
        let exp = FlowExporter::new();
        exp.set_enabled(true);
        assert!(exp.is_enabled());
        exp.add_record(FlowRecord {
            src_ip: "10.0.0.1".into(), dst_ip: "8.8.8.8".into(),
            src_port: 12345, dst_port: 443, protocol: 6,
            bytes: 1024, packets: 5,
            first_seen: 0, last_seen: 0, tcp_flags: None,
        });
        assert_eq!(exp.get_records().len(), 1);
    }
}
