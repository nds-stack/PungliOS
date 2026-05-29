use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait TenancyBackend: Send + Sync {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()>;
    async fn delete_tenant(&self, id: &str) -> Result<()>;
    async fn list_tenants(&self) -> Result<Vec<Tenant>>;
    async fn get_tenant(&self, id: &str) -> Result<Tenant>;
    async fn get_status(&self) -> Result<TenantManagerStatus>;
}

#[derive(Clone, Default)]
pub struct MockTenancy {
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
}

impl MockTenancy {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TenancyBackend for MockTenancy {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let mut map = self.tenants.write().expect("lock poisoned");
        if map.contains_key(&tenant.id) {
            bail!("tenant '{}' already exists", tenant.id);
        }
        map.insert(tenant.id.clone(), tenant.clone());
        Ok(())
    }

    async fn delete_tenant(&self, id: &str) -> Result<()> {
        let mut map = self.tenants.write().expect("lock poisoned");
        if map.remove(id).is_none() {
            bail!("tenant '{id}' not found");
        }
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let map = self.tenants.read().expect("lock poisoned");
        Ok(map.values().cloned().collect())
    }

    async fn get_tenant(&self, id: &str) -> Result<Tenant> {
        let map = self.tenants.read().expect("lock poisoned");
        map.get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("tenant '{id}' not found"))
    }

    async fn get_status(&self) -> Result<TenantManagerStatus> {
        let map = self.tenants.read().expect("lock poisoned");
        Ok(TenantManagerStatus {
            total_tenants: map.len(),
            enabled_tenants: map.values().filter(|t| t.enabled).count(),
            total_users_across_tenants: 0,
        })
    }
}

pub struct TenancyManager<T: TenancyBackend> {
    backend: T,
}

impl<T: TenancyBackend> TenancyManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        if tenant.id.is_empty() {
            bail!("tenant ID cannot be empty");
        }
        if tenant.name.is_empty() {
            bail!("tenant name cannot be empty");
        }
        self.backend.create_tenant(tenant).await
    }

    pub async fn delete_tenant(&self, id: &str) -> Result<()> {
        if id.is_empty() {
            bail!("tenant ID cannot be empty");
        }
        self.backend.delete_tenant(id).await
    }

    pub async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        self.backend.list_tenants().await
    }

    pub async fn get_tenant(&self, id: &str) -> Result<Tenant> {
        if id.is_empty() {
            bail!("tenant ID cannot be empty");
        }
        self.backend.get_tenant(id).await
    }

    pub async fn get_status(&self) -> Result<TenantManagerStatus> {
        self.backend.get_status().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_list_tenant() {
        let backend = MockTenancy::new();
        let t = Tenant {
            id: "t-001".into(),
            name: "ISP Corp".into(),
            domain: Some("isp.corp".into()),
            enabled: true,
            max_users: Some(1000),
            max_bandwidth: Some(1_000_000_000),
        };
        backend.create_tenant(&t).await.unwrap();
        assert_eq!(backend.list_tenants().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_rejected() {
        let backend = MockTenancy::new();
        let t = Tenant {
            id: "t-001".into(),
            name: "ISP Corp".into(),
            domain: None,
            enabled: true,
            max_users: None,
            max_bandwidth: None,
        };
        backend.create_tenant(&t).await.unwrap();
        assert!(backend.create_tenant(&t).await.is_err());
    }
}
