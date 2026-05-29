use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait BpfQosBackend: Send + Sync {
    async fn attach_qdisc(&self, config: &BpfQdiscConfig) -> Result<()>;
    async fn detach_qdisc(&self, iface: &str) -> Result<()>;
    async fn list_qdiscs(&self) -> Result<Vec<BpfQdiscConfig>>;
    async fn get_status(&self) -> Result<BpfQosStatus>;
}

#[derive(Clone, Default)]
pub struct MockBpfQos {
    qdiscs: Arc<RwLock<HashMap<String, BpfQdiscConfig>>>,
}

impl MockBpfQos {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BpfQosBackend for MockBpfQos {
    async fn attach_qdisc(&self, config: &BpfQdiscConfig) -> Result<()> {
        let mut qdiscs = self.qdiscs.write().expect("lock poisoned");
        if qdiscs.contains_key(&config.iface) {
            bail!("qdisc already attached on '{}'", config.iface);
        }
        qdiscs.insert(config.iface.clone(), config.clone());
        Ok(())
    }

    async fn detach_qdisc(&self, iface: &str) -> Result<()> {
        let mut qdiscs = self.qdiscs.write().expect("lock poisoned");
        if qdiscs.remove(iface).is_none() {
            bail!("no qdisc on '{iface}'");
        }
        Ok(())
    }

    async fn list_qdiscs(&self) -> Result<Vec<BpfQdiscConfig>> {
        let qdiscs = self.qdiscs.read().expect("lock poisoned");
        Ok(qdiscs.values().cloned().collect())
    }

    async fn get_status(&self) -> Result<BpfQosStatus> {
        let qdiscs = self.qdiscs.read().expect("lock poisoned");
        Ok(BpfQosStatus {
            qdiscs_count: qdiscs.len(),
            classes_count: 0,
            active_interfaces: qdiscs.keys().cloned().collect(),
        })
    }
}

pub struct BpfQosManager<T: BpfQosBackend> {
    backend: T,
}

impl<T: BpfQosBackend> BpfQosManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn attach_qdisc(&self, config: &BpfQdiscConfig) -> Result<()> {
        if config.iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.attach_qdisc(config).await
    }

    pub async fn detach_qdisc(&self, iface: &str) -> Result<()> {
        if iface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.detach_qdisc(iface).await
    }

    pub async fn list_qdiscs(&self) -> Result<Vec<BpfQdiscConfig>> {
        self.backend.list_qdiscs().await
    }

    pub async fn get_status(&self) -> Result<BpfQosStatus> {
        self.backend.get_status().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attach_list_detach() {
        let backend = MockBpfQos::new();
        let cfg = BpfQdiscConfig {
            iface: "eth0".into(),
            kind: BpfQdiscKind::FqCodel,
            rate: 1_000_000_000,
            burst: None,
            latency: None,
        };
        backend.attach_qdisc(&cfg).await.unwrap();
        assert_eq!(backend.list_qdiscs().await.unwrap().len(), 1);
        backend.detach_qdisc("eth0").await.unwrap();
        assert!(backend.list_qdiscs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_rejected() {
        let backend = MockBpfQos::new();
        let cfg = BpfQdiscConfig {
            iface: "eth0".into(),
            kind: BpfQdiscKind::Fq,
            rate: 1_000_000_000,
            burst: None,
            latency: None,
        };
        backend.attach_qdisc(&cfg).await.unwrap();
        assert!(backend.attach_qdisc(&cfg).await.is_err());
    }
}
