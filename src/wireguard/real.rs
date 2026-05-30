use super::types::*;
use super::WireguardBackend;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::process::Command;

// ─── Real WireGuard Backend via wg-quick/wg ────────────

#[cfg(feature = "real")]
pub struct RealWireguardBackend {
    interfaces: RwLock<HashMap<String, WireGuardInterface>>,
    peers: RwLock<HashMap<String, Vec<WireGuardPeer>>>,
}

#[cfg(feature = "real")]
impl RealWireguardBackend {
    pub fn new() -> Self {
        Self {
            interfaces: RwLock::new(HashMap::new()),
            peers: RwLock::new(HashMap::new()),
        }
    }

    async fn wg_cmd(args: &[&str]) -> Result<String> {
        let output = Command::new("wg")
            .args(args)
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("wg command failed: {stderr}");
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(feature = "real")]
#[async_trait]
impl WireguardBackend for RealWireguardBackend {
    async fn create_interface(&self, iface: &WireGuardInterface) -> Result<()> {
        let mut interfaces = self.interfaces.write().await;
        if interfaces.contains_key(&iface.name) {
            bail!("WireGuard interface '{}' already exists", iface.name);
        }

        // Generate keypair via wg genkey
        let privkey = Self::wg_cmd(&["genkey"]).await?;
        let pubkey = Self::wg_cmd(&["pubkey"]).await?;

        // Add interface via ip link
        Command::new("ip")
            .args(["link", "add", "dev", &iface.name, "type", "wireguard"])
            .output()
            .await?;

        // Set listen port and private key
        Self::wg_cmd(&[
            "set",
            &iface.name,
            "listen-port",
            &iface.listen_port.to_string(),
        ])
        .await?;

        // Set private key via stdin pipe
        let mut set_cmd = Command::new("wg")
            .args(["set", &iface.name, "private-key", "/dev/stdin"])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = set_cmd.stdin.take() {
            stdin.write_all(privkey.trim().as_bytes()).await?;
        }
        set_cmd.wait().await?;

        // Set MTU
        Command::new("ip")
            .args(["link", "set", "dev", &iface.name, "mtu", &iface.mtu.to_string()])
            .output()
            .await?;

        // Bring up
        Command::new("ip")
            .args(["link", "set", "dev", &iface.name, "up"])
            .output()
            .await?;

        let wg_iface = WireGuardInterface {
            name: iface.name.clone(),
            private_key: Some(privkey.trim().to_string()),
            listen_port: iface.listen_port,
            public_key: pubkey.trim().to_string(),
            enabled: true,
            mtu: iface.mtu,
        };
        interfaces.insert(iface.name.clone(), wg_iface);
        Ok(())
    }

    async fn delete_interface(&self, name: &str) -> Result<()> {
        let mut interfaces = self.interfaces.write().await;
        if interfaces.remove(name).is_none() {
            bail!("WireGuard interface '{name}' not found");
        }
        Command::new("ip")
            .args(["link", "delete", "dev", name])
            .output()
            .await?;
        Ok(())
    }

    async fn list_interfaces(&self) -> Result<Vec<WireGuardInterface>> {
        let interfaces = self.interfaces.read().await;
        Ok(interfaces.values().cloned().collect())
    }

    async fn get_interface(&self, name: &str) -> Result<WireGuardInterface> {
        let interfaces = self.interfaces.read().await;
        interfaces
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("WireGuard interface '{name}' not found"))
    }

    async fn add_peer(&self, peer: &WireGuardPeer) -> Result<()> {
        let mut peers = self.peers.write().await;
        let iface_peers = peers.entry(peer.interface.clone()).or_default();
        if iface_peers.iter().any(|p| p.public_key == peer.public_key) {
            bail!("peer '{}' already exists on {}", peer.public_key, peer.interface);
        }

        let mut args: Vec<String> = vec![
            "set".into(),
            peer.interface.clone(),
            "peer".into(),
            peer.public_key.clone(),
        ];
        if let Some(ep) = &peer.endpoint {
            let endpoint = format!("{}:{}", ep, peer.endpoint_port.unwrap_or(51820));
            args.push("endpoint".into());
            args.push(endpoint);
        }
        if let Some(ka) = peer.persistent_keepalive {
            args.push("persistent-keepalive".into());
            args.push(ka.to_string());
        }
        for ip in &peer.allowed_ips {
            args.push("allowed-ips".into());
            args.push(ip.clone());
        }
        let str_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        Self::wg_cmd(&str_refs).await?;

        iface_peers.push(peer.clone());
        Ok(())
    }

    async fn remove_peer(&self, iface: &str, pubkey: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(iface_peers) = peers.get_mut(iface) {
            iface_peers.retain(|p| p.public_key != pubkey);
        }
        Self::wg_cmd(&["set", iface, "peer", pubkey, "remove"]).await?;
        Ok(())
    }

    async fn list_peers(&self, iface: &str) -> Result<Vec<WireGuardPeer>> {
        let peers = self.peers.read().await;
        Ok(peers.get(iface).cloned().unwrap_or_default())
    }

    async fn get_status(&self) -> Result<WireGuardStatus> {
        let interfaces = self.interfaces.read().await;
        let peers = self.peers.read().await;
        let total_peers: usize = peers.values().map(|v| v.len()).sum();
        Ok(WireGuardStatus {
            interfaces_count: interfaces.len(),
            total_peers,
            enabled_interfaces: interfaces.values().filter(|i| i.enabled).count(),
        })
    }
}

// Mock when no real feature
#[cfg(not(feature = "real"))]
pub use super::backend::MockWireguardBackend as RealWireguardBackend;

#[cfg(feature = "real")]
impl Default for RealWireguardBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wg_mock_fallback() {
        #[cfg(not(feature = "real"))]
        {
            let backend = RealWireguardBackend::new();
            let status = backend.get_status().await.unwrap();
            assert_eq!(status.interfaces_count, 0);
        }
    }
}
