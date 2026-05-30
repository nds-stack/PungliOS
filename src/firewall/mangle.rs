use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MangleRule {
    pub chain: String,
    pub action: String,
    pub protocol: Option<String>,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub conn_mark: Option<u32>,
    pub packet_mark: Option<u32>,
    pub route_mark: Option<String>,
    pub enabled: bool,
}

pub struct MangleTable { rules: Mutex<Vec<MangleRule>> }

impl MangleTable {
    pub fn new() -> Self { Self { rules: Mutex::new(Vec::new()) } }
    pub fn add_rule(&self, rule: MangleRule) { self.rules.lock().unwrap().push(rule); }
    pub fn remove_rule(&self, idx: usize) { self.rules.lock().unwrap().remove(idx); }
    pub fn list_rules(&self) -> Vec<MangleRule> { self.rules.lock().unwrap().clone() }
}

impl Default for MangleTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mangle() {
        let m = MangleTable::new();
        m.add_rule(MangleRule {
            chain: "prerouting".into(), action: "mark-connection".into(),
            protocol: Some("tcp".into()), src_addr: Some("10.0.0.0/8".into()),
            dst_addr: None, src_port: None, dst_port: Some(80),
            conn_mark: Some(1), packet_mark: None, route_mark: None, enabled: true,
        });
        assert_eq!(m.list_rules().len(), 1);
    }
}
