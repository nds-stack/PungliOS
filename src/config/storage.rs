use anyhow::{Context, Result};
use std::{fs, path::Path};

use super::schema::NetworkConfig;

pub const BINARY_CONFIG_PATH: &str = "/etc/punglios/config.bin";

pub fn save_binary(config: &NetworkConfig, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bytes = bincode::serialize(config).context("failed to serialize config to bincode")?;

    fs::write(path, &bytes)
        .with_context(|| format!("failed to write binary config to {}", path.display()))?;

    Ok(())
}

pub fn load_binary(path: &Path) -> Result<NetworkConfig> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read binary config from {}", path.display()))?;

    let config: NetworkConfig =
        bincode::deserialize(&bytes).context("failed to deserialize binary config")?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_binary() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.bin");

        let config = NetworkConfig {
            interfaces: vec![super::super::schema::InterfaceDef {
                name: "eth0".into(),
                mtu: Some(1500),
                addresses: vec!["10.0.0.1".into()],
                vlan_id: None,
                bridge: None,
            }],
            ..Default::default()
        };

        save_binary(&config, &path).unwrap();
        let loaded = load_binary(&path).unwrap();
        assert_eq!(loaded.interfaces.len(), 1);
        assert_eq!(loaded.interfaces[0].name, "eth0");
    }

    #[test]
    fn test_save_default_config() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.bin");

        let config = NetworkConfig::default();
        save_binary(&config, &path).unwrap();
        let loaded = load_binary(&path).unwrap();
        assert_eq!(loaded.conntrack.max, 262_144);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = Path::new("/nonexistent/path/config.bin");
        assert!(load_binary(path).is_err());
    }
}
