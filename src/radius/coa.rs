use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoaAction {
    Disconnect,
    ChangeBandwidth { upload: u32, download: u32 },
    ReAuthenticate,
    ChangeAddress(String),
}

pub struct RadiusCoa {
    server: String,
    secret: String,
    coa_port: u16,
}

impl RadiusCoa {
    pub fn new(server: &str, secret: &str, coa_port: u16) -> Self {
        Self { server: server.to_string(), secret: secret.to_string(), coa_port }
    }

    pub async fn send_coa(&self, session_id: &str, action: &CoaAction) -> Result<String> {
        if session_id.is_empty() { bail!("session ID required"); }
        // Mock: just log the action
        Ok(format!("CoA sent for session {session_id}: {action:?}"))
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<String> {
        self.send_coa(session_id, &CoaAction::Disconnect).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_coa() {
        let coa = RadiusCoa::new("10.0.0.1", "secret123", 3799);
        let result = coa.disconnect("session-12345").await.unwrap();
        assert!(result.contains("session-12345"));
    }
}
