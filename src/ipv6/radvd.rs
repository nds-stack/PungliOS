use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterAdvertisement {
    pub interface: String,
    pub enabled: bool,
    pub managed: bool,
    pub other_config: bool,
    pub mtu: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub cur_hop_limit: u8,
    pub prefix: String,
    pub prefix_length: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub dns_servers: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, Default)]
pub struct RadvdManager {
    configs: Arc<Mutex<Vec<RouterAdvertisement>>>,
}

impl RadvdManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(&self, ra: RouterAdvertisement) -> Result<()> {
        if ra.interface.is_empty() {
            bail!("interface required");
        }
        if ra.prefix.is_empty() {
            bail!("prefix required");
        }
        self.configs.lock().await.push(ra);
        Ok(())
    }

    pub async fn remove(&self, interface: &str) -> Result<()> {
        let mut configs = self.configs.lock().await;
        let len = configs.len();
        configs.retain(|c| c.interface != interface);
        if configs.len() == len {
            bail!("RA not found for {interface}");
        }
        Ok(())
    }

    pub async fn list(&self) -> Vec<RouterAdvertisement> {
        self.configs.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ra_add_list() {
        let mgr = RadvdManager::new();
        mgr.add(RouterAdvertisement {
            interface: "br0".into(),
            enabled: true,
            managed: false,
            other_config: false,
            mtu: 1500,
            reachable_time: 0,
            retrans_timer: 0,
            cur_hop_limit: 64,
            prefix: "2001:db8::".into(),
            prefix_length: 64,
            preferred_lifetime: 604800,
            valid_lifetime: 2592000,
            dns_servers: vec![],
        })
        .await
        .unwrap();
        assert_eq!(mgr.list().await.len(), 1);
    }
}
