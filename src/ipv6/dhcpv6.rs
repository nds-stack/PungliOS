use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcpv6PdConfig {
    pub interface: String,
    pub enabled: bool,
    pub prefix_hint: String,
    pub prefix_length: u8,
    pub delegated_prefix: Option<String>,
    pub rapid_commit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dhcpv6IaNa {
    pub interface: String,
    pub iaid: u32,
    pub address: Option<Ipv6Addr>,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

#[async_trait]
pub trait Dhcpv6Backend: Send + Sync {
    async fn request_pd(&self, config: &Dhcpv6PdConfig) -> Result<String>;
    async fn release_pd(&self, interface: &str) -> Result<()>;
    async fn renew_pd(&self, interface: &str) -> Result<String>;
    async fn get_iana(&self, interface: &str) -> Result<Dhcpv6IaNa>;
}

#[derive(Clone, Default)]
pub struct MockDhcpv6Backend {
    pds: Arc<RwLock<HashMap<String, String>>>,
}

impl MockDhcpv6Backend {
    pub fn new() -> Self { Self::default() }
}

#[async_trait]
impl Dhcpv6Backend for MockDhcpv6Backend {
    async fn request_pd(&self, config: &Dhcpv6PdConfig) -> Result<String> {
        if config.interface.is_empty() {
            bail!("interface cannot be empty");
        }
        let prefix = "2001:db8:1::/48".to_string();
        self.pds.write().await.insert(config.interface.clone(), prefix.clone());
        Ok(prefix)
    }
    async fn release_pd(&self, interface: &str) -> Result<()> {
        self.pds.write().await.remove(interface);
        Ok(())
    }
    async fn renew_pd(&self, interface: &str) -> Result<String> {
        self.pds.read().await.get(interface).cloned().ok_or_else(|| anyhow::anyhow!("no PD for {interface}"))
    }
    async fn get_iana(&self, _interface: &str) -> Result<Dhcpv6IaNa> {
        Ok(Dhcpv6IaNa {
            interface: "eth0".into(),
            iaid: 1,
            address: Some("2001:db8::100".parse().unwrap()),
            preferred_lifetime: 604800,
            valid_lifetime: 2592000,
        })
    }
}

pub struct Dhcpv6Manager<T: Dhcpv6Backend> {
    backend: T,
}

impl<T: Dhcpv6Backend> Dhcpv6Manager<T> {
    pub fn new(backend: T) -> Self { Self { backend } }
    pub async fn request_pd(&self, config: &Dhcpv6PdConfig) -> Result<String> {
        if config.interface.is_empty() { bail!("interface required"); }
        self.backend.request_pd(config).await
    }
    pub async fn release_pd(&self, iface: &str) -> Result<()> {
        if iface.is_empty() { bail!("interface required"); }
        self.backend.release_pd(iface).await
    }
    pub async fn get_iana(&self, iface: &str) -> Result<Dhcpv6IaNa> {
        self.backend.get_iana(iface).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_request_pd() {
        let mgr = Dhcpv6Manager::new(MockDhcpv6Backend::new());
        let config = Dhcpv6PdConfig {
            interface: "wan0".into(), enabled: true,
            prefix_hint: "::/48".into(), prefix_length: 48,
            delegated_prefix: None, rapid_commit: true,
        };
        let prefix = mgr.request_pd(&config).await.unwrap();
        assert!(prefix.contains("2001:db8"));
    }
}
