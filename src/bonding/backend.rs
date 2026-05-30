use super::types::*;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait BondingBackend: Send + Sync {
    async fn create_bond(&self, bond: &BondInterface) -> Result<()>;
    async fn delete_bond(&self, name: &str) -> Result<()>;
    async fn list_bonds(&self) -> Result<Vec<BondInterface>>;
    async fn get_bond(&self, name: &str) -> Result<BondInterface>;
    async fn add_slave(&self, bond: &str, slave: &str) -> Result<()>;
    async fn remove_slave(&self, bond: &str, slave: &str) -> Result<()>;
    async fn set_bond_up(&self, name: &str) -> Result<()>;
    async fn set_bond_down(&self, name: &str) -> Result<()>;
    async fn get_status(&self) -> Result<BondStatus>;
}

#[derive(Clone, Default)]
pub struct MockBondingBackend {
    bonds: Arc<RwLock<HashMap<String, BondInterface>>>,
    active_slaves: Arc<RwLock<HashMap<String, String>>>,
}

impl MockBondingBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BondingBackend for MockBondingBackend {
    async fn create_bond(&self, bond: &BondInterface) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        if bonds.contains_key(&bond.name) {
            bail!("bond '{}' already exists", bond.name);
        }
        bonds.insert(bond.name.clone(), bond.clone());
        Ok(())
    }

    async fn delete_bond(&self, name: &str) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        bonds.remove(name);
        Ok(())
    }

    async fn list_bonds(&self) -> Result<Vec<BondInterface>> {
        let bonds = self.bonds.read().await;
        Ok(bonds.values().cloned().collect())
    }

    async fn get_bond(&self, name: &str) -> Result<BondInterface> {
        let bonds = self.bonds.read().await;
        bonds
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("bond '{name}' not found"))
    }

    async fn add_slave(&self, bond_name: &str, slave: &str) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        let bond = bonds
            .get_mut(bond_name)
            .ok_or_else(|| anyhow::anyhow!("bond '{bond_name}' not found"))?;
        if bond.slaves.contains(&slave.to_string()) {
            bail!("slave '{slave}' already in bond '{bond_name}'");
        }
        bond.slaves.push(slave.to_string());
        Ok(())
    }

    async fn remove_slave(&self, bond_name: &str, slave: &str) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        let bond = bonds
            .get_mut(bond_name)
            .ok_or_else(|| anyhow::anyhow!("bond '{bond_name}' not found"))?;
        bond.slaves.retain(|s| s != slave);
        Ok(())
    }

    async fn set_bond_up(&self, name: &str) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        let bond = bonds
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("bond '{name}' not found"))?;
        bond.enabled = true;
        Ok(())
    }

    async fn set_bond_down(&self, name: &str) -> Result<()> {
        let mut bonds = self.bonds.write().await;
        let bond = bonds
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("bond '{name}' not found"))?;
        bond.enabled = false;
        Ok(())
    }

    async fn get_status(&self) -> Result<BondStatus> {
        let bonds = self.bonds.read().await;
        let total_slaves: usize = bonds.values().map(|b| b.slaves.len()).sum();
        let enabled_count = bonds.values().filter(|b| b.enabled).count();
        let bonds_list: Vec<BondInfo> = bonds
            .values()
            .map(|b| BondInfo {
                name: b.name.clone(),
                mode: b.mode,
                slave_count: b.slaves.len(),
                enabled: b.enabled,
                active_slave: b.slaves.first().cloned(),
            })
            .collect();
        Ok(BondStatus {
            bonds_count: bonds.len(),
            total_slaves,
            enabled_count,
            bonds: bonds_list,
        })
    }
}

pub struct BondingManager<T: BondingBackend> {
    backend: T,
}

impl<T: BondingBackend> BondingManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn create_bond(&self, bond: &BondInterface) -> Result<()> {
        if bond.name.is_empty() {
            bail!("bond name cannot be empty");
        }
        if bond.name.len() > 15 {
            bail!("bond name too long (max 15 chars)");
        }
        self.backend.create_bond(bond).await
    }

    pub async fn delete_bond(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("bond name cannot be empty");
        }
        self.backend.delete_bond(name).await
    }

    pub async fn list_bonds(&self) -> Result<Vec<BondInterface>> {
        self.backend.list_bonds().await
    }

    pub async fn get_bond(&self, name: &str) -> Result<BondInterface> {
        if name.is_empty() {
            bail!("bond name cannot be empty");
        }
        self.backend.get_bond(name).await
    }

    pub async fn add_slave(&self, bond: &str, slave: &str) -> Result<()> {
        if bond.is_empty() || slave.is_empty() {
            bail!("bond and slave names required");
        }
        self.backend.add_slave(bond, slave).await
    }

    pub async fn remove_slave(&self, bond: &str, slave: &str) -> Result<()> {
        if bond.is_empty() || slave.is_empty() {
            bail!("bond and slave names required");
        }
        self.backend.remove_slave(bond, slave).await
    }

    pub async fn set_bond_up(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("bond name cannot be empty");
        }
        self.backend.set_bond_up(name).await
    }

    pub async fn set_bond_down(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("bond name cannot be empty");
        }
        self.backend.set_bond_down(name).await
    }

    pub async fn get_status(&self) -> Result<BondStatus> {
        self.backend.get_status().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_list_bond() {
        let mgr = BondingManager::new(MockBondingBackend::new());
        let bond = BondInterface::new("bond0", BondMode::Ieee8023ad);
        mgr.create_bond(&bond).await.unwrap();
        let bonds = mgr.list_bonds().await.unwrap();
        assert_eq!(bonds.len(), 1);
    }

    #[tokio::test]
    async fn test_add_remove_slave() {
        let mgr = BondingManager::new(MockBondingBackend::new());
        mgr.create_bond(&BondInterface::new("bond0", BondMode::ActiveBackup))
            .await
            .unwrap();
        mgr.add_slave("bond0", "eth0").await.unwrap();
        mgr.add_slave("bond0", "eth1").await.unwrap();
        let bond = mgr.get_bond("bond0").await.unwrap();
        assert_eq!(bond.slaves.len(), 2);
        mgr.remove_slave("bond0", "eth0").await.unwrap();
        let bond = mgr.get_bond("bond0").await.unwrap();
        assert_eq!(bond.slaves.len(), 1);
    }

    #[tokio::test]
    async fn test_bond_up_down() {
        let mgr = BondingManager::new(MockBondingBackend::new());
        mgr.create_bond(&BondInterface::new("bond0", BondMode::RoundRobin))
            .await
            .unwrap();
        mgr.set_bond_down("bond0").await.unwrap();
        let bond = mgr.get_bond("bond0").await.unwrap();
        assert!(!bond.enabled);
        mgr.set_bond_up("bond0").await.unwrap();
        let bond = mgr.get_bond("bond0").await.unwrap();
        assert!(bond.enabled);
    }

    #[tokio::test]
    async fn test_duplicate_bond_rejected() {
        let mgr = BondingManager::new(MockBondingBackend::new());
        let bond = BondInterface::new("bond0", BondMode::XOR);
        mgr.create_bond(&bond).await.unwrap();
        assert!(mgr.create_bond(&bond).await.is_err());
    }
}
