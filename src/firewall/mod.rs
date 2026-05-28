pub mod chain;
pub mod nat;
pub mod rule;
pub mod zone;

use crate::traits::{FirewallRule, FirewallZone, NetlinkFirewall};
use anyhow::{Result, bail};

pub struct FirewallManager<T: NetlinkFirewall> {
    backend: T,
}

impl<T: NetlinkFirewall> FirewallManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn list_rules(&self, zone: &str) -> Result<Vec<FirewallRule>> {
        if zone.is_empty() {
            bail!("zone name cannot be empty");
        }
        self.backend.list_rules(zone).await
    }

    pub async fn add_rule(&self, rule: &FirewallRule) -> Result<u64> {
        if rule.zone.is_empty() {
            bail!("rule zone cannot be empty");
        }
        if rule.chain.is_empty() {
            bail!("rule chain cannot be empty");
        }
        self.backend.add_rule(rule).await
    }

    pub async fn delete_rule(&self, handle: u64) -> Result<()> {
        self.backend.delete_rule(handle).await
    }

    pub async fn flush_rules(&self) -> Result<()> {
        self.backend.flush_rules().await
    }

    pub async fn create_zone(&self, zone: &FirewallZone) -> Result<()> {
        if zone.name.is_empty() {
            bail!("zone name cannot be empty");
        }
        self.backend.create_zone(zone).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{FirewallAction, MockBackend};

    fn setup() -> FirewallManager<MockBackend> {
        FirewallManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_create_zone() {
        let mgr = setup();
        let zone = FirewallZone {
            name: "lan".into(),
            interfaces: vec!["eth0".into()],
            forward: Some(FirewallAction::Accept),
            input: Some(FirewallAction::Accept),
            output: Some(FirewallAction::Accept),
        };
        mgr.create_zone(&zone).await.unwrap();
        let rules = mgr.list_rules("lan").await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_list_rules() {
        let mgr = setup();
        mgr.create_zone(&FirewallZone {
            name: "wan".into(),
            interfaces: vec!["eth1".into()],
            forward: Some(FirewallAction::Drop),
            input: Some(FirewallAction::Drop),
            output: Some(FirewallAction::Accept),
        })
        .await
        .unwrap();

        let handle = mgr
            .add_rule(&FirewallRule {
                handle: 0,
                zone: "wan".into(),
                chain: "forward".into(),
                protocol: Some("tcp".into()),
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: Some(443),
                action: FirewallAction::Accept,
                position: 0,
            })
            .await
            .unwrap();
        assert!(handle > 0);

        let rules = mgr.list_rules("wan").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dst_port, Some(443));
    }

    #[tokio::test]
    async fn test_delete_rule() {
        let mgr = setup();
        let handle = mgr
            .add_rule(&FirewallRule {
                handle: 0,
                zone: "lan".into(),
                chain: "forward".into(),
                protocol: None,
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                action: FirewallAction::Drop,
                position: 0,
            })
            .await
            .unwrap();

        mgr.delete_rule(handle).await.unwrap();
        let rules = mgr.list_rules("lan").await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_flush_rules() {
        let mgr = setup();
        for _ in 0..5 {
            mgr.add_rule(&FirewallRule {
                handle: 0,
                zone: "lan".into(),
                chain: "forward".into(),
                protocol: None,
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                action: FirewallAction::Accept,
                position: 0,
            })
            .await
            .unwrap();
        }
        mgr.flush_rules().await.unwrap();
        let rules = mgr.list_rules("lan").await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_empty_zone_rejected() {
        let mgr = setup();
        assert!(
            mgr.create_zone(&FirewallZone {
                name: "".into(),
                interfaces: vec![],
                forward: None,
                input: None,
                output: None,
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("cannot be empty")
        );
    }
}
