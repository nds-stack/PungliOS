use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub use_tls: bool,
}

impl Default for EmailConfig {
    fn default() -> Self { Self { enabled: false, server: "smtp.example.com".into(), port: 587, username: None, password: None, from: "punglios@local".into(), to: vec![], use_tls: true } }
}

pub struct EmailManager { config: Mutex<EmailConfig> }

impl EmailManager {
    pub fn new() -> Self { Self { config: Mutex::new(EmailConfig::default()) } }
    pub fn get_config(&self) -> EmailConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: EmailConfig) { *self.config.lock().unwrap() = c; }
    pub async fn send(&self, subject: &str, body: &str) -> Result<String> {
        let cfg = self.get_config();
        if cfg.to.is_empty() { anyhow::bail!("no recipients configured"); }
        // Mock: use mail command or curl
        let _ = subject; let _ = body;
        Ok("email sent (mock)".into())
    }
}

impl Default for EmailManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_email_config() {
        let mgr = EmailManager::new();
        assert_eq!(mgr.get_config().port, 587);
    }
}
