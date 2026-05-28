use crate::traits::{NatKind, NatRule, NetlinkNat};
use anyhow::{Result, bail};
use std::fmt;

pub struct NatManager<T: NetlinkNat> {
    backend: T,
}

impl<T: NetlinkNat + fmt::Debug> fmt::Debug for NatManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatManager")
            .field("backend", &self.backend)
            .finish()
    }
}

impl<T: NetlinkNat> NatManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn add_snat(
        &self,
        iface: &str,
        src_addr: Option<std::net::IpAddr>,
        to_addr: Option<std::net::IpAddr>,
    ) -> Result<u64> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let rule = NatRule {
            handle: 0,
            iface: iface.to_string(),
            kind: NatKind::Snat,
            src_addr,
            dst_addr: None,
            to_addr,
            to_port: None,
        };
        self.backend.add_rule(&rule).await
    }

    pub async fn add_dnat(
        &self,
        iface: &str,
        dst_addr: Option<std::net::IpAddr>,
        to_addr: Option<std::net::IpAddr>,
        to_port: Option<u16>,
    ) -> Result<u64> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let rule = NatRule {
            handle: 0,
            iface: iface.to_string(),
            kind: NatKind::Dnat,
            src_addr: None,
            dst_addr,
            to_addr,
            to_port,
        };
        self.backend.add_rule(&rule).await
    }

    pub async fn add_masquerade(&self, iface: &str) -> Result<u64> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let rule = NatRule {
            handle: 0,
            iface: iface.to_string(),
            kind: NatKind::Masquerade,
            src_addr: None,
            dst_addr: None,
            to_addr: None,
            to_port: None,
        };
        self.backend.add_rule(&rule).await
    }

    pub async fn delete_rule(&self, handle: u64) -> Result<()> {
        self.backend.delete_rule(handle).await
    }

    pub async fn list_rules(&self) -> Result<Vec<NatRule>> {
        self.backend.list_rules().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBackend;

    fn setup() -> NatManager<MockBackend> {
        NatManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_add_snat() {
        let mgr = setup();
        let handle = mgr.add_snat("eth0", None, None).await.unwrap();
        assert!(handle > 0);
    }

    #[tokio::test]
    async fn test_add_dnat() {
        let mgr = setup();
        let dst: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let to: std::net::IpAddr = "192.168.1.100".parse().unwrap();
        let handle = mgr
            .add_dnat("eth0", Some(dst), Some(to), Some(8080))
            .await
            .unwrap();
        assert!(handle > 0);
    }

    #[tokio::test]
    async fn test_add_masquerade() {
        let mgr = setup();
        let handle = mgr.add_masquerade("wan").await.unwrap();
        assert!(handle > 0);
    }

    #[tokio::test]
    async fn test_list_rules() {
        let mgr = setup();
        mgr.add_masquerade("wan").await.unwrap();
        mgr.add_snat("lan", None, None).await.unwrap();
        let rules = mgr.list_rules().await.unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_rule() {
        let mgr = setup();
        let handle = mgr.add_masquerade("wan").await.unwrap();
        mgr.delete_rule(handle).await.unwrap();
        assert!(mgr.list_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_empty_iface_rejected() {
        let mgr = setup();
        let err = mgr.add_snat("", None, None).await.unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
    }
}
