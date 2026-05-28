use anyhow::{Context, Result};
use std::{fs, path::PathBuf};

use super::schema::NetworkConfig;
use super::storage;

pub const BACKUP_EXTENSION: &str = ".bak";

pub struct Transaction {
    config: NetworkConfig,
    backup_path: Option<PathBuf>,
    commit_path: Option<PathBuf>,
    committed: bool,
}

impl Transaction {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            config,
            backup_path: None,
            commit_path: None,
            committed: false,
        }
    }

    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut NetworkConfig {
        &mut self.config
    }

    pub fn commit(&mut self, path: &std::path::Path) -> Result<()> {
        if self.committed {
            anyhow::bail!("transaction already committed");
        }

        self.commit_path = Some(path.to_path_buf());

        let backup_path = path.with_extension(
            path.extension()
                .map(|e| format!("{}.bak", e.to_string_lossy()))
                .unwrap_or_else(|| "bak".to_string()),
        );

        if path.exists() {
            fs::copy(path, &backup_path)
                .with_context(|| format!("failed to create backup at {}", backup_path.display()))?;
            self.backup_path = Some(backup_path);
        }

        storage::save_binary(&self.config, path)?;
        self.committed = true;

        Ok(())
    }

    pub fn rollback(&self) -> Result<()> {
        if !self.committed {
            anyhow::bail!("transaction not yet committed, nothing to roll back");
        }

        match (&self.backup_path, &self.commit_path) {
            (Some(backup), Some(commit)) => {
                if backup.exists() {
                    fs::copy(backup, commit)
                        .with_context(|| {
                            format!(
                                "failed to restore backup from {} to {}",
                                backup.display(),
                                commit.display()
                            )
                        })?;
                    fs::remove_file(backup)?;
                } else if commit.exists() {
                    fs::remove_file(commit)?;
                }
                Ok(())
            }
            (None, Some(commit)) => {
                if commit.exists() {
                    fs::remove_file(commit)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_commit_and_rollback_no_backup() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.bin");

        let config = NetworkConfig::default();
        let mut tx = Transaction::new(config);
        tx.commit(&config_path).unwrap();
        assert!(config_path.exists());

        tx.rollback().unwrap();
        assert!(!config_path.exists());
    }

    #[test]
    fn test_commit_twice_rejected() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.bin");

        let config = NetworkConfig::default();
        let mut tx = Transaction::new(config);
        tx.commit(&config_path).unwrap();

        let err = tx.commit(&config_path).unwrap_err();
        assert!(err.to_string().contains("already committed"));
    }

    #[test]
    fn test_rollback_before_commit_rejected() {
        let config = NetworkConfig::default();
        let tx = Transaction::new(config);
        let err = tx.rollback().unwrap_err();
        assert!(err.to_string().contains("not yet committed"));
    }

    #[test]
    fn test_rollback_restores_backup() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.bin");

        let mut orig = NetworkConfig::default();
        orig.interfaces.push(super::super::schema::InterfaceDef {
            name: "eth0".into(),
            mtu: Some(1500),
            addresses: vec![],
            vlan_id: None,
            bridge: None,
        });

        storage::save_binary(&orig, &config_path).unwrap();

        let mut tx = Transaction::new(orig.clone());
        tx.config_mut().interfaces.clear();
        tx.commit(&config_path).unwrap();

        let after = storage::load_binary(&config_path).unwrap();
        assert!(after.interfaces.is_empty());

        tx.rollback().unwrap();

        let restored = storage::load_binary(&config_path).unwrap();
        assert_eq!(restored.interfaces.len(), 1);
        assert_eq!(restored.interfaces[0].name, "eth0");
    }

    #[test]
    fn test_create_dirs_on_commit() {
        let dir = TempDir::new().unwrap();
        let deep_path = dir.path().join("nested/deep/config.bin");

        let config = NetworkConfig::default();
        let mut tx = Transaction::new(config);
        tx.commit(&deep_path).unwrap();
        assert!(deep_path.exists());
    }

    #[test]
    fn test_commit_creates_no_backup_on_first_write() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.bin");

        let config = NetworkConfig::default();
        let mut tx = Transaction::new(config);
        tx.commit(&config_path).unwrap();

        assert!(tx.backup_path.is_none());
    }
}
