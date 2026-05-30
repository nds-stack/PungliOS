use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAclRule {
    pub bridge: String,
    pub action: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub vlan_id: Option<u16>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub enabled: bool,
}

pub struct BridgeAcl { rules: Mutex<Vec<BridgeAclRule>> }

impl BridgeAcl {
    pub fn new() -> Self { Self { rules: Mutex::new(Vec::new()) } }
    pub fn add_rule(&self, rule: BridgeAclRule) { self.rules.lock().unwrap().push(rule); }
    pub fn remove_rule(&self, idx: usize) { self.rules.lock().unwrap().remove(idx); }
    pub fn list_rules(&self) -> Vec<BridgeAclRule> { self.rules.lock().unwrap().clone() }
}

impl Default for BridgeAcl { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_acl() {
        let acl = BridgeAcl::new();
        acl.add_rule(BridgeAclRule {
            bridge: "br0".into(), action: "drop".into(),
            src_mac: None, dst_mac: None, vlan_id: None,
            src_port: Some("eth0".into()), dst_port: None, enabled: true,
        });
        assert_eq!(acl.list_rules().len(), 1);
    }
}
