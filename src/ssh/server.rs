use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub enabled: bool,
    pub port: u16,
    pub allow_root: bool,
    pub password_auth: bool,
    pub key_auth: bool,
    pub max_sessions: u32,
    pub allowed_networks: Vec<String>,
    pub timeout_secs: u32,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 22,
            allow_root: true,
            password_auth: true,
            key_auth: true,
            max_sessions: 10,
            allowed_networks: vec!["0.0.0.0/0".into()],
            timeout_secs: 300,
        }
    }
}

pub struct SshManager {
    config: Mutex<SshConfig>,
}

impl SshManager {
    pub fn new() -> Self { Self { config: Mutex::new(SshConfig::default()) } }
    pub fn get_config(&self) -> SshConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: SshConfig) { *self.config.lock().unwrap() = c; }
    pub async fn restart(&self) -> String { "SSH service restart triggered (mock)".into() }
}

impl Default for SshManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_ssh() { let m = SshManager::new(); assert_eq!(m.get_config().port, 22); }
    #[test]
    fn test_set_port() { let m = SshManager::new(); let mut c = m.get_config(); c.port = 2222; m.set_config(c); assert_eq!(m.get_config().port, 2222); }
}
