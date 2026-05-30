use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrfConfig {
    pub name: String,
    pub table_id: u32,
    pub interfaces: Vec<String>,
    pub description: Option<String>,
    pub enabled: bool,
}

#[async_trait]
pub trait VrfBackend: Send + Sync {
    async fn create_vrf(&self, vrf: &VrfConfig) -> Result<()>;
    async fn delete_vrf(&self, name: &str) -> Result<()>;
    async fn list_vrfs(&self) -> Result<Vec<VrfConfig>>;
    async fn get_vrf(&self, name: &str) -> Result<VrfConfig>;
    async fn add_interface(&self, vrf: &str, iface: &str) -> Result<()>;
    async fn remove_interface(&self, vrf: &str, iface: &str) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MockVrfBackend {
    vrfs: Arc<RwLock<HashMap<String, VrfConfig>>>,
}

impl MockVrfBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VrfBackend for MockVrfBackend {
    async fn create_vrf(&self, vrf: &VrfConfig) -> Result<()> {
        let mut vrfs = self.vrfs.write().await;
        if vrfs.contains_key(&vrf.name) {
            bail!("VRF '{}' already exists", vrf.name);
        }
        vrfs.insert(vrf.name.clone(), vrf.clone());
        Ok(())
    }

    async fn delete_vrf(&self, name: &str) -> Result<()> {
        let mut vrfs = self.vrfs.write().await;
        vrfs.remove(name);
        Ok(())
    }

    async fn list_vrfs(&self) -> Result<Vec<VrfConfig>> {
        let vrfs = self.vrfs.read().await;
        Ok(vrfs.values().cloned().collect())
    }

    async fn get_vrf(&self, name: &str) -> Result<VrfConfig> {
        let vrfs = self.vrfs.read().await;
        vrfs
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("VRF '{name}' not found"))
    }

    async fn add_interface(&self, vrf_name: &str, iface: &str) -> Result<()> {
        let mut vrfs = self.vrfs.write().await;
        let vrf = vrfs
            .get_mut(vrf_name)
            .ok_or_else(|| anyhow::anyhow!("VRF '{vrf_name}' not found"))?;
        if vrf.interfaces.contains(&iface.to_string()) {
            bail!("interface '{iface}' already in VRF '{vrf_name}'");
        }
        vrf.interfaces.push(iface.to_string());
        Ok(())
    }

    async fn remove_interface(&self, vrf_name: &str, iface: &str) -> Result<()> {
        let mut vrfs = self.vrfs.write().await;
        let vrf = vrfs
            .get_mut(vrf_name)
            .ok_or_else(|| anyhow::anyhow!("VRF '{vrf_name}' not found"))?;
        vrf.interfaces.retain(|i| i != iface);
        Ok(())
    }
}

pub struct VrfManager<T: VrfBackend> {
    backend: T,
}

impl<T: VrfBackend> VrfManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn create_vrf(&self, vrf: &VrfConfig) -> Result<()> {
        if vrf.name.is_empty() {
            bail!("VRF name cannot be empty");
        }
        if vrf.table_id == 0 || vrf.table_id > 2_147_483_647 {
            bail!("VRF table ID must be 1-2147483647");
        }
        self.backend.create_vrf(vrf).await
    }

    pub async fn delete_vrf(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("VRF name cannot be empty");
        }
        self.backend.delete_vrf(name).await
    }

    pub async fn list_vrfs(&self) -> Result<Vec<VrfConfig>> {
        self.backend.list_vrfs().await
    }

    pub async fn get_vrf(&self, name: &str) -> Result<VrfConfig> {
        if name.is_empty() {
            bail!("VRF name cannot be empty");
        }
        self.backend.get_vrf(name).await
    }

    pub async fn add_interface(&self, vrf: &str, iface: &str) -> Result<()> {
        if vrf.is_empty() || iface.is_empty() {
            bail!("VRF name and interface name required");
        }
        self.backend.add_interface(vrf, iface).await
    }

    pub async fn remove_interface(&self, vrf: &str, iface: &str) -> Result<()> {
        if vrf.is_empty() || iface.is_empty() {
            bail!("VRF name and interface name required");
        }
        self.backend.remove_interface(vrf, iface).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_list_vrf() {
        let mgr = VrfManager::new(MockVrfBackend::new());
        mgr.create_vrf(&VrfConfig {
            name: "mgmt".into(),
            table_id: 100,
            interfaces: vec![],
            description: Some("management".into()),
            enabled: true,
        })
        .await
        .unwrap();
        let vrfs = mgr.list_vrfs().await.unwrap();
        assert_eq!(vrfs.len(), 1);
    }

    #[tokio::test]
    async fn test_add_remove_interface() {
        let mgr = VrfManager::new(MockVrfBackend::new());
        mgr.create_vrf(&VrfConfig {
            name: "blue".into(),
            table_id: 200,
            interfaces: vec![],
            description: None,
            enabled: true,
        })
        .await
        .unwrap();
        mgr.add_interface("blue", "eth1").await.unwrap();
        let vrf = mgr.get_vrf("blue").await.unwrap();
        assert_eq!(vrf.interfaces.len(), 1);
        mgr.remove_interface("blue", "eth1").await.unwrap();
        let vrf = mgr.get_vrf("blue").await.unwrap();
        assert!(vrf.interfaces.is_empty());
    }

    #[tokio::test]
    async fn test_duplicate_vrf_rejected() {
        let mgr = VrfManager::new(MockVrfBackend::new());
        let vrf = VrfConfig {
            name: "dup".into(),
            table_id: 1,
            interfaces: vec![],
            description: None,
            enabled: true,
        };
        mgr.create_vrf(&vrf).await.unwrap();
        assert!(mgr.create_vrf(&vrf).await.is_err());
    }
}
