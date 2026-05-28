pub mod class;
pub mod fq_codel;
pub mod htb;

use crate::traits::{ClassConfig, NetlinkQos, QdiscConfig, QdiscKind};
use anyhow::{Result, bail};
use std::fmt;

pub struct QosManager<T: NetlinkQos> {
    backend: T,
}

impl<T: NetlinkQos + fmt::Debug> fmt::Debug for QosManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QosManager")
            .field("backend", &self.backend)
            .finish()
    }
}

impl<T: NetlinkQos> QosManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn add_qdisc(&self, config: &QdiscConfig) -> Result<()> {
        if config.iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.add_qdisc(config).await
    }

    pub async fn delete_qdisc(&self, iface: &str, handle: u32) -> Result<()> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.delete_qdisc(iface, handle).await
    }

    pub async fn add_class(&self, config: &ClassConfig) -> Result<()> {
        if config.iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        if config.rate == 0 {
            bail!("rate must be greater than 0");
        }
        if config.ceil > 0 && config.ceil < config.rate {
            bail!("ceil cannot be less than rate");
        }
        self.backend.add_class(config).await
    }

    pub async fn delete_class(&self, iface: &str, classid: u32) -> Result<()> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.delete_class(iface, classid).await
    }

    pub async fn create_htb_root(&self, iface: &str, rate: u64) -> Result<()> {
        let config = QdiscConfig {
            kind: QdiscKind::Htb,
            iface: iface.to_string(),
            handle: 0x10,
            parent: 0,
            rate: Some(rate),
            ceil: Some(rate),
        };
        self.add_qdisc(&config).await
    }

    pub async fn create_user_class(
        &self,
        iface: &str,
        classid: u32,
        rate: u64,
        ceil: u64,
    ) -> Result<()> {
        let config = ClassConfig {
            iface: iface.to_string(),
            classid,
            parent: 0x10,
            rate,
            ceil,
            burst: None,
            cburst: None,
            priority: 3,
        };
        self.add_class(&config).await
    }

    pub async fn attach_fq_codel(&self, iface: &str, parent: u32) -> Result<()> {
        let config = QdiscConfig {
            kind: QdiscKind::FqCodel,
            iface: iface.to_string(),
            handle: 0,
            parent,
            rate: None,
            ceil: None,
        };
        self.add_qdisc(&config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBackend;

    fn setup() -> QosManager<MockBackend> {
        QosManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_add_qdisc() {
        let mgr = setup();
        let config = QdiscConfig {
            kind: QdiscKind::Htb,
            iface: "eth0".into(),
            handle: 0x10,
            parent: 0,
            rate: Some(1_000_000_000),
            ceil: Some(1_000_000_000),
        };
        mgr.add_qdisc(&config).await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_qdisc() {
        let mgr = setup();
        mgr.delete_qdisc("eth0", 0x10).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_class() {
        let mgr = setup();
        let config = ClassConfig {
            iface: "eth0".into(),
            classid: 0x10_01,
            parent: 0x10,
            rate: 100_000_000,
            ceil: 100_000_000,
            burst: None,
            cburst: None,
            priority: 3,
        };
        mgr.add_class(&config).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_class_zero_rate_rejected() {
        let mgr = setup();
        let err = mgr
            .add_class(&ClassConfig {
                iface: "eth0".into(),
                classid: 1,
                parent: 0x10,
                rate: 0,
                ceil: 0,
                burst: None,
                cburst: None,
                priority: 3,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rate must be greater than 0"));
    }

    #[tokio::test]
    async fn test_create_htb_root() {
        let mgr = setup();
        mgr.create_htb_root("eth0", 1_000_000_000).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_user_class() {
        let mgr = setup();
        mgr.create_user_class("eth0", 0x10_01, 50_000_000, 100_000_000)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_attach_fq_codel() {
        let mgr = setup();
        mgr.attach_fq_codel("eth0", 0x10_01).await.unwrap();
    }
}
