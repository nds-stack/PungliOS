use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireGuardInterface {
    pub name: String,
    #[serde(skip_serializing)]
    pub private_key: Option<String>,
    pub listen_port: u16,
    pub public_key: String,
    pub enabled: bool,
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireGuardPeer {
    pub interface: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub endpoint_port: Option<u16>,
    pub persistent_keepalive: Option<u16>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WireGuardStatus {
    pub interfaces_count: usize,
    pub total_peers: usize,
    pub enabled_interfaces: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_interface_creation() {
        let iface = WireGuardInterface {
            name: "wg0".into(),
            private_key: None,
            listen_port: 51820,
            public_key: "xTU4Q6VUn/9JlRZ5UpnWmFXxUj/W0M6tRul0P73WMj4=".into(),
            enabled: true,
            mtu: 1420,
        };
        assert_eq!(iface.name, "wg0");
        assert_eq!(iface.listen_port, 51820);
    }

    #[test]
    fn test_wg_peer_creation() {
        let peer = WireGuardPeer {
            interface: "wg0".into(),
            public_key: "xTU4Q6VUn/9JlRZ5UpnWmFXxUj/W0M6tRul0P73WMj4=".into(),
            allowed_ips: vec!["10.0.0.2/32".into()],
            endpoint: Some("vpn.example.com".into()),
            endpoint_port: Some(51820),
            persistent_keepalive: Some(25),
            enabled: true,
        };
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.public_key.len(), 44);
    }
}
