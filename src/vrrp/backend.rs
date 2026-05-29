use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait VrrpBackend: Send + Sync {
    async fn create_instance(&self, inst: &VrrpInstance) -> Result<()>;
    async fn delete_instance(&self, name: &str) -> Result<()>;
    async fn list_instances(&self) -> Result<Vec<VrrpInstance>>;
    async fn get_status(&self) -> Result<VrrpStatus>;
}

#[derive(Clone, Default)]
pub struct MockVrrp {
    instances: Arc<RwLock<HashMap<String, VrrpInstance>>>,
}

impl MockVrrp {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VrrpBackend for MockVrrp {
    async fn create_instance(&self, inst: &VrrpInstance) -> Result<()> {
        let mut map = self.instances.write().expect("lock poisoned");
        if map.contains_key(&inst.name) {
            bail!("VRRP instance '{}' already exists", inst.name);
        }
        map.insert(inst.name.clone(), inst.clone());
        Ok(())
    }

    async fn delete_instance(&self, name: &str) -> Result<()> {
        let mut map = self.instances.write().expect("lock poisoned");
        if map.remove(name).is_none() {
            bail!("VRRP instance '{name}' not found");
        }
        Ok(())
    }

    async fn list_instances(&self) -> Result<Vec<VrrpInstance>> {
        let map = self.instances.read().expect("lock poisoned");
        Ok(map.values().cloned().collect())
    }

    async fn get_status(&self) -> Result<VrrpStatus> {
        let map = self.instances.read().expect("lock poisoned");
        let best = map.values().max_by_key(|i| i.priority);
        Ok(VrrpStatus {
            master_instance: best.map(|i| i.name.clone()),
            instances_count: map.len(),
            master_count: 1.min(map.len()),
            backup_count: map.len().saturating_sub(1),
        })
    }
}

pub struct VrrpManager<T: VrrpBackend> {
    backend: T,
}

impl<T: VrrpBackend> VrrpManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn create_instance(&self, inst: &VrrpInstance) -> Result<()> {
        if inst.name.is_empty() {
            bail!("instance name cannot be empty");
        }
        if inst.interface.is_empty() {
            bail!("interface cannot be empty");
        }
        if inst.virtual_ip.is_empty() {
            bail!("virtual IP cannot be empty");
        }
        self.backend.create_instance(inst).await
    }

    pub async fn delete_instance(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("instance name cannot be empty");
        }
        self.backend.delete_instance(name).await
    }

    pub async fn list_instances(&self) -> Result<Vec<VrrpInstance>> {
        self.backend.list_instances().await
    }

    pub async fn get_status(&self) -> Result<VrrpStatus> {
        self.backend.get_status().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_instance(name: &str) -> VrrpInstance {
        VrrpInstance {
            vrid: 1,
            name: name.into(),
            interface: "eth0".into(),
            priority: 100,
            virtual_ip: "10.0.0.254".into(),
            virtual_prefix: 24,
            advert_interval: 1,
            preempt: true,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_create_list_instance() {
        let backend = MockVrrp::new();
        backend
            .create_instance(&test_instance("vip-1"))
            .await
            .unwrap();
        let list = backend.list_instances().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_instance() {
        let backend = MockVrrp::new();
        backend
            .create_instance(&test_instance("vip-1"))
            .await
            .unwrap();
        backend.delete_instance("vip-1").await.unwrap();
        assert!(backend.list_instances().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_rejected() {
        let backend = MockVrrp::new();
        backend
            .create_instance(&test_instance("vip-1"))
            .await
            .unwrap();
        assert!(
            backend
                .create_instance(&test_instance("vip-1"))
                .await
                .is_err()
        );
    }
}
