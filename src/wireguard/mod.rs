pub mod backend;
pub mod types;

pub use backend::*;
pub use types::*;

use anyhow::Result;

pub struct WireGuardManager<T: WireguardBackend> {
    backend: T,
}

impl<T: WireguardBackend> WireGuardManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub async fn create_interface(&self, iface: &WireGuardInterface) -> Result<()> {
        if iface.name.is_empty() {
            anyhow::bail!("interface name cannot be empty");
        }
        if iface.listen_port == 0 {
            anyhow::bail!("listen port must be 1-65535");
        }
        if iface.public_key.is_empty() {
            anyhow::bail!("public key cannot be empty");
        }
        self.backend.create_interface(iface).await
    }

    pub async fn delete_interface(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            anyhow::bail!("interface name cannot be empty");
        }
        self.backend.delete_interface(name).await
    }

    pub async fn list_interfaces(&self) -> Result<Vec<WireGuardInterface>> {
        self.backend.list_interfaces().await
    }

    pub async fn get_interface(&self, name: &str) -> Result<WireGuardInterface> {
        if name.is_empty() {
            anyhow::bail!("interface name cannot be empty");
        }
        self.backend.get_interface(name).await
    }

    pub async fn add_peer(&self, peer: &WireGuardPeer) -> Result<()> {
        if peer.interface.is_empty() {
            anyhow::bail!("peer must specify an interface");
        }
        if peer.public_key.is_empty() || peer.public_key.len() != 44 {
            anyhow::bail!("invalid WireGuard public key (must be 44 base64 chars)");
        }
        if peer.allowed_ips.is_empty() {
            anyhow::bail!("at least one allowed IP required");
        }
        self.backend.add_peer(peer).await
    }

    pub async fn remove_peer(&self, iface: &str, pubkey: &str) -> Result<()> {
        if iface.is_empty() || pubkey.is_empty() {
            anyhow::bail!("interface and public key required");
        }
        self.backend.remove_peer(iface, pubkey).await
    }

    pub async fn list_peers(&self, iface: &str) -> Result<Vec<WireGuardPeer>> {
        if iface.is_empty() {
            anyhow::bail!("interface name cannot be empty");
        }
        self.backend.list_peers(iface).await
    }

    pub async fn get_status(&self) -> Result<WireGuardStatus> {
        self.backend.get_status().await
    }
}
