use anyhow::{Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhcpClientState {
    Initial,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Released,
}

impl std::fmt::Display for DhcpClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::Selecting => write!(f, "selecting"),
            Self::Requesting => write!(f, "requesting"),
            Self::Bound => write!(f, "bound"),
            Self::Renewing => write!(f, "renewing"),
            Self::Rebinding => write!(f, "rebinding"),
            Self::Released => write!(f, "released"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub interface: String,
    pub server_id: IpAddr,
    pub offered_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
    pub renew_seconds: u32,
    pub rebind_seconds: u32,
    pub acquired_at: u64,
}

impl DhcpLease {
    pub fn expires_at(&self) -> u64 {
        self.acquired_at + self.lease_seconds as u64
    }

    pub fn renew_at(&self) -> u64 {
        self.acquired_at + self.renew_seconds as u64
    }

    pub fn rebind_at(&self) -> u64 {
        self.acquired_at + self.rebind_seconds as u64
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            > self.expires_at()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpClientConfig {
    pub interface: String,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub use_gateway_as_dns: bool,
}

impl Default for DhcpClientConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            hostname: None,
            client_id: None,
            use_gateway_as_dns: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpClientInfo {
    pub interface: String,
    pub state: DhcpClientState,
    pub lease: Option<DhcpLease>,
    pub config: DhcpClientConfig,
    pub is_enabled: bool,
}

#[async_trait]
pub trait DhcpClientBackend: Send + Sync {
    async fn discover(&self, interface: &str, config: &DhcpClientConfig) -> Result<DhcpLease>;
    async fn request(&self, interface: &str, lease: &DhcpLease) -> Result<()>;
    async fn renew(&self, interface: &str, lease: &DhcpLease) -> Result<DhcpLease>;
    async fn release(&self, interface: &str, lease: &DhcpLease) -> Result<()>;
    async fn get_status(&self, interface: &str) -> Result<DhcpClientInfo>;
}

#[derive(Debug, Clone)]
pub struct MockDhcpClient;

#[async_trait]
impl DhcpClientBackend for MockDhcpClient {
    async fn discover(&self, interface: &str, config: &DhcpClientConfig) -> Result<DhcpLease> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(DhcpLease {
            interface: interface.to_string(),
            server_id: "192.168.1.1".parse().unwrap(),
            offered_ip: match config.use_gateway_as_dns {
                true => "192.168.1.100".parse().unwrap(),
                false => "10.0.0.100".parse().unwrap(),
            },
            subnet_mask: "255.255.255.0".parse().unwrap(),
            gateway: "192.168.1.1".parse().unwrap(),
            dns_servers: vec!["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()],
            lease_seconds: 86400,
            renew_seconds: 43200,
            rebind_seconds: 75600,
            acquired_at: now,
        })
    }

    async fn request(&self, interface: &str, _lease: &DhcpLease) -> Result<()> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        Ok(())
    }

    async fn renew(&self, interface: &str, _lease: &DhcpLease) -> Result<DhcpLease> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.discover(interface, &DhcpClientConfig::default()).await
    }

    async fn release(&self, interface: &str, _lease: &DhcpLease) -> Result<()> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        Ok(())
    }

    async fn get_status(&self, interface: &str) -> Result<DhcpClientInfo> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        let lease = self
            .discover(interface, &DhcpClientConfig::default())
            .await?;
        Ok(DhcpClientInfo {
            interface: interface.to_string(),
            state: DhcpClientState::Bound,
            lease: Some(lease),
            config: DhcpClientConfig::default(),
            is_enabled: true,
        })
    }
}

pub struct DhcpClientManager<T: DhcpClientBackend> {
    backend: T,
}

impl<T: DhcpClientBackend> DhcpClientManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn discover(
        &self,
        interface: &str,
        config: &DhcpClientConfig,
    ) -> Result<DhcpLease> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.discover(interface, config).await
    }

    pub async fn request(&self, interface: &str, lease: &DhcpLease) -> Result<()> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.request(interface, lease).await
    }

    pub async fn renew(&self, interface: &str, lease: &DhcpLease) -> Result<DhcpLease> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.renew(interface, lease).await
    }

    pub async fn release(&self, interface: &str, lease: &DhcpLease) -> Result<()> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.release(interface, lease).await
    }

    pub async fn get_status(&self, interface: &str) -> Result<DhcpClientInfo> {
        if interface.is_empty() {
            bail!("interface name cannot be empty");
        }
        self.backend.get_status(interface).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> DhcpClientManager<MockDhcpClient> {
        DhcpClientManager::new(MockDhcpClient)
    }

    #[tokio::test]
    async fn test_discover() {
        let mgr = setup();
        let lease = mgr
            .discover("wan0", &DhcpClientConfig::default())
            .await
            .unwrap();
        assert_eq!(lease.interface, "wan0");
        assert!(lease.lease_seconds > 0);
    }

    #[tokio::test]
    async fn test_request() {
        let mgr = setup();
        let lease = mgr
            .discover("wan0", &DhcpClientConfig::default())
            .await
            .unwrap();
        assert!(mgr.request("wan0", &lease).await.is_ok());
    }

    #[tokio::test]
    async fn test_renew() {
        let mgr = setup();
        let lease = mgr
            .discover("wan0", &DhcpClientConfig::default())
            .await
            .unwrap();
        let renewed = mgr.renew("wan0", &lease).await.unwrap();
        assert_eq!(renewed.interface, "wan0");
    }

    #[tokio::test]
    async fn test_release() {
        let mgr = setup();
        let lease = mgr
            .discover("wan0", &DhcpClientConfig::default())
            .await
            .unwrap();
        assert!(mgr.release("wan0", &lease).await.is_ok());
    }

    #[tokio::test]
    async fn test_empty_interface_rejected() {
        let mgr = setup();
        assert!(mgr.discover("", &DhcpClientConfig::default()).await.is_err());
    }

    #[tokio::test]
    async fn test_get_status() {
        let mgr = setup();
        let status = mgr.get_status("wan0").await.unwrap();
        assert_eq!(status.state, DhcpClientState::Bound);
        assert!(status.is_enabled);
    }
}
