use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct L2tpTunnel {
    pub name: String,
    pub local_ip: String,
    pub remote_ip: String,
    pub local_id: u32,
    pub remote_id: u32,
    pub enabled: bool,
    pub mtu: u16,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct L2tpSession {
    pub tunnel: String,
    pub session_id: u32,
    pub username: String,
    pub ip_address: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub uptime_secs: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct L2tpStatus {
    pub tunnels_count: usize,
    pub sessions_count: usize,
    pub active_sessions: usize,
    pub tunnels: Vec<L2tpTunnel>,
}

#[async_trait]
pub trait L2tpBackend: Send + Sync {
    async fn create_tunnel(&self, tunnel: &L2tpTunnel) -> Result<()>;
    async fn delete_tunnel(&self, name: &str) -> Result<()>;
    async fn list_tunnels(&self) -> Result<Vec<L2tpTunnel>>;
    async fn get_tunnel(&self, name: &str) -> Result<L2tpTunnel>;
    async fn get_status(&self) -> Result<L2tpStatus>;
}

#[derive(Clone, Default)]
pub struct MockL2tpBackend {
    tunnels: Arc<RwLock<HashMap<String, L2tpTunnel>>>,
    sessions: Arc<RwLock<Vec<L2tpSession>>>,
}

impl MockL2tpBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl L2tpBackend for MockL2tpBackend {
    async fn create_tunnel(&self, tunnel: &L2tpTunnel) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        if tunnels.contains_key(&tunnel.name) {
            bail!("L2TP tunnel '{}' already exists", tunnel.name);
        }
        tunnels.insert(tunnel.name.clone(), tunnel.clone());
        Ok(())
    }

    async fn delete_tunnel(&self, name: &str) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        tunnels.remove(name);
        Ok(())
    }

    async fn list_tunnels(&self) -> Result<Vec<L2tpTunnel>> {
        let tunnels = self.tunnels.read().await;
        Ok(tunnels.values().cloned().collect())
    }

    async fn get_tunnel(&self, name: &str) -> Result<L2tpTunnel> {
        let tunnels = self.tunnels.read().await;
        tunnels
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("L2TP tunnel '{name}' not found"))
    }

    async fn get_status(&self) -> Result<L2tpStatus> {
        let tunnels = self.tunnels.read().await;
        let sessions = self.sessions.read().await;
        Ok(L2tpStatus {
            tunnels_count: tunnels.len(),
            sessions_count: sessions.len(),
            active_sessions: sessions.iter().filter(|s| s.enabled).count(),
            tunnels: tunnels.values().cloned().collect(),
        })
    }
}

pub struct L2tpManager<T: L2tpBackend> {
    backend: T,
}

impl<T: L2tpBackend> L2tpManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn create_tunnel(&self, tunnel: &L2tpTunnel) -> Result<()> {
        if tunnel.name.is_empty() {
            bail!("tunnel name cannot be empty");
        }
        if tunnel.remote_ip.is_empty() {
            bail!("remote IP cannot be empty");
        }
        self.backend.create_tunnel(tunnel).await
    }

    pub async fn delete_tunnel(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            bail!("tunnel name cannot be empty");
        }
        self.backend.delete_tunnel(name).await
    }

    pub async fn list_tunnels(&self) -> Result<Vec<L2tpTunnel>> {
        self.backend.list_tunnels().await
    }

    pub async fn get_tunnel(&self, name: &str) -> Result<L2tpTunnel> {
        if name.is_empty() {
            bail!("tunnel name cannot be empty");
        }
        self.backend.get_tunnel(name).await
    }

    pub async fn get_status(&self) -> Result<L2tpStatus> {
        self.backend.get_status().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_list_tunnel() {
        let mgr = L2tpManager::new(MockL2tpBackend::new());
        mgr.create_tunnel(&L2tpTunnel {
            name: "tun1".into(),
            local_ip: "10.0.0.1".into(),
            remote_ip: "10.0.0.2".into(),
            local_id: 1,
            remote_id: 2,
            enabled: true,
            mtu: 1460,
            description: None,
        })
        .await
        .unwrap();
        let tunnels = mgr.list_tunnels().await.unwrap();
        assert_eq!(tunnels.len(), 1);
    }

    #[tokio::test]
    async fn test_status() {
        let mgr = L2tpManager::new(MockL2tpBackend::new());
        let status = mgr.get_status().await.unwrap();
        assert_eq!(status.tunnels_count, 0);
    }
}
