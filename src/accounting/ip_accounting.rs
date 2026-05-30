use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAccountRecord {
    pub ip: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

pub struct IpAccounting { records: Mutex<HashMap<String, IpAccountRecord>>, enabled: Mutex<bool> }

impl IpAccounting {
    pub fn new() -> Self { Self { records: Mutex::new(HashMap::new()), enabled: Mutex::new(false) } }
    pub fn set_enabled(&self, val: bool) { *self.enabled.lock().unwrap() = val; }
    pub fn is_enabled(&self) -> bool { *self.enabled.lock().unwrap() }
    pub fn record(&self, ip: &str, bytes_in: u64, bytes_out: u64, pkts_in: u64, pkts_out: u64) {
        let mut r = self.records.lock().unwrap();
        let entry = r.entry(ip.to_string()).or_insert(IpAccountRecord { ip: ip.to_string(), bytes_in: 0, bytes_out: 0, packets_in: 0, packets_out: 0 });
        entry.bytes_in += bytes_in; entry.bytes_out += bytes_out; entry.packets_in += pkts_in; entry.packets_out += pkts_out;
    }
    pub fn get_records(&self) -> Vec<IpAccountRecord> { self.records.lock().unwrap().values().cloned().collect() }
    pub fn clear(&self) { self.records.lock().unwrap().clear(); }
}

impl Default for IpAccounting { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ip_accounting() {
        let a = IpAccounting::new();
        a.set_enabled(true); a.record("10.0.0.1", 1000, 2000, 10, 20); a.record("10.0.0.1", 500, 500, 5, 5);
        assert_eq!(a.get_records().len(), 1);
        assert_eq!(a.get_records()[0].bytes_in, 1500);
    }
}
