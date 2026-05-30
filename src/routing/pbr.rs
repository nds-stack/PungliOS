use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbrRule {
    pub name: String,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub protocol: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub mark: Option<u32>,
    pub table_id: u32,
    pub enabled: bool,
}

pub struct PbrManager { rules: Mutex<Vec<PbrRule>> }

impl PbrManager {
    pub fn new() -> Self { Self { rules: Mutex::new(Vec::new()) } }
    pub fn add_rule(&self, rule: PbrRule) { self.rules.lock().unwrap().push(rule); }
    pub fn remove_rule(&self, idx: usize) { self.rules.lock().unwrap().remove(idx); }
    pub fn list_rules(&self) -> Vec<PbrRule> { self.rules.lock().unwrap().clone() }
}

impl Default for PbrManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pbr() {
        let pbr = PbrManager::new();
        pbr.add_rule(PbrRule {
            name: "voip".into(), src_addr: Some("10.10.0.0/16".into()),
            dst_addr: None, protocol: Some("udp".into()),
            src_port: None, dst_port: Some(5060),
            mark: None, table_id: 100, enabled: true,
        });
        assert_eq!(pbr.list_rules().len(), 1);
    }
}
