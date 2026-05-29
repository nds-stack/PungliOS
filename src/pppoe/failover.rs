use serde::{Deserialize, Serialize};

/// A PPPoE uplink connection to an ISP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PppUplink {
    pub name: String,
    pub interface: String,
    pub isp_name: String,
    pub priority: u8,
    pub enabled: bool,
    pub connected: bool,
    pub failover_count: u64,
}

/// Current status of the PPPoE failover system.
#[derive(Debug, Clone, Serialize)]
pub struct PppFailoverStatus {
    pub active_uplink: Option<String>,
    pub total_uplinks: usize,
    pub connected_uplinks: usize,
    pub last_failover_at: Option<u64>,
    pub uptime_secs: u64,
}

use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait PppFailoverBackend: Send + Sync {
    async fn list_uplinks(&self) -> Result<Vec<PppUplink>>;
    async fn add_uplink(&self, uplink: &PppUplink) -> Result<()>;
    async fn remove_uplink(&self, name: &str) -> Result<()>;
    async fn get_status(&self) -> Result<PppFailoverStatus>;
    async fn trigger_failover(&self) -> Result<String>;
    async fn set_uplink_priority(&self, name: &str, priority: u8) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MockPppFailover {
    uplinks: Arc<RwLock<HashMap<String, PppUplink>>>,
    failover_time: Arc<RwLock<Option<u64>>>,
    start_time: u64,
}

impl MockPppFailover {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            uplinks: Arc::new(RwLock::new(HashMap::new())),
            failover_time: Arc::new(RwLock::new(None)),
            start_time: now,
        }
    }
}

#[async_trait]
impl PppFailoverBackend for MockPppFailover {
    async fn list_uplinks(&self) -> Result<Vec<PppUplink>> {
        let uplinks = self.uplinks.read().expect("lock poisoned");
        Ok(uplinks.values().cloned().collect())
    }

    async fn add_uplink(&self, uplink: &PppUplink) -> Result<()> {
        let mut uplinks = self.uplinks.write().expect("lock poisoned");
        if uplinks.contains_key(&uplink.name) {
            bail!("uplink '{}' already exists", uplink.name);
        }
        uplinks.insert(uplink.name.clone(), uplink.clone());
        Ok(())
    }

    async fn remove_uplink(&self, name: &str) -> Result<()> {
        let mut uplinks = self.uplinks.write().expect("lock poisoned");
        if uplinks.remove(name).is_none() {
            bail!("uplink '{name}' not found");
        }
        Ok(())
    }

    async fn get_status(&self) -> Result<PppFailoverStatus> {
        let uplinks = self.uplinks.read().expect("lock poisoned");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let connected: Vec<String> = uplinks
            .values()
            .filter(|u| u.connected)
            .map(|u| u.name.clone())
            .collect();
        let active = connected.first().cloned();
        let ft = *self.failover_time.read().expect("lock poisoned");
        Ok(PppFailoverStatus {
            active_uplink: active,
            total_uplinks: uplinks.len(),
            connected_uplinks: connected.len(),
            last_failover_at: ft,
            uptime_secs: now.saturating_sub(self.start_time),
        })
    }

    async fn trigger_failover(&self) -> Result<String> {
        let mut uplinks = self.uplinks.write().expect("lock poisoned");
        let connected: Vec<String> = uplinks
            .values()
            .filter(|u| u.connected)
            .map(|u| u.name.clone())
            .collect();
        if connected.len() < 2 {
            bail!("need at least 2 connected uplinks for failover");
        }
        let mut sorted = uplinks
            .values_mut()
            .filter(|u| u.connected)
            .collect::<Vec<&mut PppUplink>>();
        sorted.sort_by_key(|u| u.priority);
        if let Some(next) = sorted.first() {
            let name = next.name.clone();
            for u in uplinks.values_mut() {
                if u.name == name {
                    u.failover_count += 1;
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            *self.failover_time.write().expect("lock poisoned") = Some(now);
            return Ok(name);
        }
        bail!("no available uplink for failover");
    }

    async fn set_uplink_priority(&self, name: &str, priority: u8) -> Result<()> {
        let mut uplinks = self.uplinks.write().expect("lock poisoned");
        let uplink = uplinks
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("uplink '{name}' not found"))?;
        uplink.priority = priority;
        Ok(())
    }
}

pub struct PppFailoverManager<T: PppFailoverBackend> {
    backend: T,
}

impl<T: PppFailoverBackend> PppFailoverManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn list_uplinks(&self) -> Result<Vec<PppUplink>> {
        self.backend.list_uplinks().await
    }

    pub async fn add_uplink(&self, uplink: &PppUplink) -> Result<()> {
        if uplink.name.is_empty() {
            bail!("uplink name cannot be empty");
        }
        if uplink.interface.is_empty() {
            bail!("interface cannot be empty");
        }
        self.backend.add_uplink(uplink).await
    }

    pub async fn remove_uplink(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("uplink name cannot be empty");
        }
        self.backend.remove_uplink(name).await
    }

    pub async fn get_status(&self) -> Result<PppFailoverStatus> {
        self.backend.get_status().await
    }

    pub async fn trigger_failover(&self) -> Result<String> {
        self.backend.trigger_failover().await
    }

    pub async fn set_uplink_priority(&self, name: &str, priority: u8) -> Result<()> {
        if name.is_empty() {
            bail!("uplink name cannot be empty");
        }
        self.backend.set_uplink_priority(name, priority).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_list_uplink() {
        let backend = MockPppFailover::new();
        let uplink = PppUplink {
            name: "isp-a".into(),
            interface: "ppp0".into(),
            isp_name: "ISP A".into(),
            priority: 10,
            enabled: true,
            connected: true,
            failover_count: 0,
        };
        backend.add_uplink(&uplink).await.unwrap();
        let list = backend.list_uplinks().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn test_failover_needs_two() {
        let backend = MockPppFailover::new();
        let uplink = PppUplink {
            name: "isp-a".into(),
            interface: "ppp0".into(),
            isp_name: "ISP A".into(),
            priority: 10,
            enabled: true,
            connected: true,
            failover_count: 0,
        };
        backend.add_uplink(&uplink).await.unwrap();
        assert!(backend.trigger_failover().await.is_err());
    }

    #[tokio::test]
    async fn test_failover_switches_to_highest_priority() {
        let backend = MockPppFailover::new();
        backend
            .add_uplink(&PppUplink {
                name: "isp-a".into(),
                interface: "ppp0".into(),
                isp_name: "ISP A".into(),
                priority: 20,
                enabled: true,
                connected: true,
                failover_count: 0,
            })
            .await
            .unwrap();
        backend
            .add_uplink(&PppUplink {
                name: "isp-b".into(),
                interface: "ppp1".into(),
                isp_name: "ISP B".into(),
                priority: 10,
                enabled: true,
                connected: true,
                failover_count: 0,
            })
            .await
            .unwrap();
        let active = backend.trigger_failover().await.unwrap();
        assert_eq!(active, "isp-b");
    }
}
