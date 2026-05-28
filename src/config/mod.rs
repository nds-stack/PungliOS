pub mod schema;
pub mod storage;
pub mod transaction;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use schema::NetworkConfig;
use storage::{load_binary, save_binary};
use transaction::Transaction;

const CONFIG_DIR: &str = "/etc/punglios";
const CONFIG_YAML: &str = "/etc/punglios/config.yaml";
const CONFIG_BINARY: &str = "/etc/punglios/config.bin";

pub struct ConfigEngine {
    config_dir: PathBuf,
    yaml_path: PathBuf,
    binary_path: PathBuf,
    current: NetworkConfig,
}

impl ConfigEngine {
    pub fn new() -> Self {
        Self {
            config_dir: PathBuf::from(CONFIG_DIR),
            yaml_path: PathBuf::from(CONFIG_YAML),
            binary_path: PathBuf::from(CONFIG_BINARY),
            current: NetworkConfig::default(),
        }
    }

    pub fn with_paths(config_dir: &str, yaml_path: &str, binary_path: &str) -> Self {
        Self {
            config_dir: PathBuf::from(config_dir),
            yaml_path: PathBuf::from(yaml_path),
            binary_path: PathBuf::from(binary_path),
            current: NetworkConfig::default(),
        }
    }

    pub fn current(&self) -> &NetworkConfig {
        &self.current
    }

    pub fn current_mut(&mut self) -> &mut NetworkConfig {
        &mut self.current
    }

    pub fn load_yaml(&mut self) -> Result<()> {
        if !self.yaml_path.exists() {
            anyhow::bail!("config file not found: {}", self.yaml_path.display());
        }

        let yaml_str = std::fs::read_to_string(&self.yaml_path)
            .with_context(|| format!("failed to read {}", self.yaml_path.display()))?;

        let config: NetworkConfig = serde_yaml::from_str(&yaml_str)
            .with_context(|| format!("failed to parse YAML from {}", self.yaml_path.display()))?;

        self.current = config;
        Ok(())
    }

    pub fn load_binary(&mut self) -> Result<()> {
        if !self.binary_path.exists() {
            anyhow::bail!("binary config not found: {}", self.binary_path.display());
        }
        self.current = load_binary(&self.binary_path)?;
        Ok(())
    }

    pub fn save_yaml(&self) -> Result<()> {
        let yaml_str =
            serde_yaml::to_string(&self.current).context("failed to serialize config to YAML")?;
        std::fs::write(&self.yaml_path, &yaml_str)
            .with_context(|| format!("failed to write {}", self.yaml_path.display()))?;
        Ok(())
    }

    pub fn save_binary(&self) -> Result<()> {
        save_binary(&self.current, &self.binary_path)
    }

    pub fn begin_transaction(&mut self) -> Transaction {
        Transaction::new(self.current.clone())
    }

    pub fn apply_transaction(&mut self, tx: &mut Transaction) -> Result<()> {
        tx.commit(&self.binary_path)?;
        self.current = tx.config().clone();
        Ok(())
    }

    pub fn set_yaml_path(&mut self, path: &str) {
        self.yaml_path = PathBuf::from(path);
    }

    pub fn set_binary_path(&mut self, path: &str) {
        self.binary_path = PathBuf::from(path);
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn yaml_path(&self) -> &Path {
        &self.yaml_path
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn load_or_default(&mut self, prefer_yaml: bool) {
        if prefer_yaml {
            if self.yaml_path.exists() {
                if let Err(e) = self.load_yaml() {
                    tracing::warn!("failed to load YAML config: {e}");
                    if self.binary_path.exists() {
                        if let Err(e) = self.load_binary() {
                            tracing::warn!("binary fallback also failed: {e}, using defaults");
                        }
                    } else {
                        tracing::warn!("using defaults");
                    }
                }
            } else if self.binary_path.exists()
                && let Err(e) = self.load_binary()
            {
                tracing::warn!("failed to load binary config: {e}, using defaults");
            }
        } else if self.binary_path.exists() {
            if let Err(e) = self.load_binary() {
                tracing::warn!("failed to load binary config: {e}, trying YAML");
                if self.yaml_path.exists()
                    && let Err(e) = self.load_yaml()
                {
                    tracing::warn!("failed to load YAML config: {e}, using defaults");
                }
            }
        } else if self.yaml_path.exists()
            && let Err(e) = self.load_yaml()
        {
            tracing::warn!("failed to load YAML config: {e}, using defaults");
        }
    }
}

impl Default for ConfigEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_yaml_roundtrip() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("config.yaml");
        let bin = dir.path().join("config.bin");

        let mut engine = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );

        engine.current_mut().interfaces.push(schema::InterfaceDef {
            name: "eth0".into(),
            mtu: Some(9000),
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        });

        engine.save_yaml().unwrap();
        assert!(yaml.exists());

        let mut engine2 = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );
        engine2.load_yaml().unwrap();
        assert_eq!(engine2.current().interfaces.len(), 1);
        assert_eq!(engine2.current().interfaces[0].mtu, Some(9000));
    }

    #[test]
    fn test_binary_roundtrip() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("config.yaml");
        let bin = dir.path().join("config.bin");

        let mut engine = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );

        engine.current_mut().conntrack.max = 500_000;
        engine.save_binary().unwrap();

        let mut engine2 = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );
        engine2.load_binary().unwrap();
        assert_eq!(engine2.current().conntrack.max, 500_000);
    }

    #[test]
    fn test_transactional_apply() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("config.yaml");
        let bin = dir.path().join("config.bin");

        let mut engine = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );

        let mut tx = engine.begin_transaction();
        tx.config_mut().interfaces.push(schema::InterfaceDef {
            name: "eth0".into(),
            mtu: None,
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        });

        engine.apply_transaction(&mut tx).unwrap();
        assert_eq!(engine.current().interfaces.len(), 1);
        assert!(bin.exists());
    }

    #[test]
    fn test_load_nonexistent_yaml() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("nonexistent.yaml");
        let bin = dir.path().join("config.bin");

        let mut engine = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );

        let err = engine.load_yaml().unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_load_or_default_without_files() {
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("config.yaml");
        let bin = dir.path().join("config.bin");

        let mut engine = ConfigEngine::with_paths(
            dir.path().to_str().unwrap(),
            yaml.to_str().unwrap(),
            bin.to_str().unwrap(),
        );

        engine.load_or_default(true);
        assert_eq!(engine.current().interfaces.len(), 0);
    }
}
