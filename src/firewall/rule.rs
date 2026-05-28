use crate::traits::{FirewallAction, FirewallRule};

pub fn allow(zone: &str, chain: &str) -> FirewallRule {
    FirewallRule {
        handle: 0,
        zone: zone.to_string(),
        chain: chain.to_string(),
        protocol: None,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        action: FirewallAction::Accept,
        positions: 0,
    }
}

pub fn drop(zone: &str, chain: &str) -> FirewallRule {
    FirewallRule {
        handle: 0,
        zone: zone.to_string(),
        chain: chain.to_string(),
        protocol: None,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        action: FirewallAction::Drop,
        positions: 0,
    }
}

pub fn reject(zone: &str, chain: &str) -> FirewallRule {
    FirewallRule {
        handle: 0,
        zone: zone.to_string(),
        chain: chain.to_string(),
        protocol: None,
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        action: FirewallAction::Reject,
        positions: 0,
    }
}
