use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6FirewallRule {
    pub chain: String,
    pub action: String,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub protocol: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub hop_limit: Option<u8>,
    pub flow_label: Option<u32>,
    pub icmp_type: Option<u8>,
    pub enabled: bool,
}

#[derive(Debug, Default)]
pub struct Ipv6Firewall {
    rules: Mutex<Vec<Ipv6FirewallRule>>,
}

impl Ipv6Firewall {
    pub fn new() -> Self { Self::default() }
    pub fn add_rule(&self, rule: Ipv6FirewallRule) {
        self.rules.lock().unwrap().push(rule);
    }
    pub fn remove_rule(&self, index: usize) {
        self.rules.lock().unwrap().remove(index);
    }
    pub fn list_rules(&self) -> Vec<Ipv6FirewallRule> {
        self.rules.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ipv6_firewall() {
        let fw = Ipv6Firewall::new();
        fw.add_rule(Ipv6FirewallRule {
            chain: "input".into(), action: "accept".into(),
            src_addr: None, dst_addr: None, protocol: Some("icmpv6".into()),
            src_port: None, dst_port: None, hop_limit: None,
            flow_label: None, icmp_type: Some(135), enabled: true,
        });
        assert_eq!(fw.list_rules().len(), 1);
    }
}
