use super::tunnel::L2tpSession;
use anyhow::{Result, bail};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct L2tpSessionManager {
    sessions: RwLock<HashMap<String, Vec<L2tpSession>>>,
}

impl L2tpSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn create_session(&self, tunnel: &str, username: &str) -> Result<L2tpSession> {
        if tunnel.is_empty() || username.is_empty() {
            bail!("tunnel and username required");
        }
        let mut sessions = self.sessions.write().await;
        let session = L2tpSession {
            tunnel: tunnel.to_string(),
            session_id: (sessions.len() + 1) as u32,
            username: username.to_string(),
            ip_address: None,
            rx_bytes: 0,
            tx_bytes: 0,
            uptime_secs: 0,
            enabled: true,
        };
        sessions.entry(tunnel.to_string()).or_default().push(session.clone());
        Ok(session)
    }

    pub async fn end_session(&self, tunnel: &str, session_id: u32) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(tunnel_sessions) = sessions.get_mut(tunnel) {
            tunnel_sessions.retain(|s| s.session_id != session_id);
            Ok(())
        } else {
            bail!("no sessions found for tunnel '{tunnel}'")
        }
    }

    pub async fn list_sessions(&self, tunnel: &str) -> Vec<L2tpSession> {
        self.sessions
            .read()
            .await
            .get(tunnel)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn update_stats(&self, tunnel: &str, session_id: u32, rx: u64, tx: u64) {
        let mut sessions = self.sessions.write().await;
        if let Some(tunnel_sessions) = sessions.get_mut(tunnel) {
            if let Some(session) = tunnel_sessions
                .iter_mut()
                .find(|s| s.session_id == session_id)
            {
                session.rx_bytes += rx;
                session.tx_bytes += tx;
            }
        }
    }
}

impl Default for L2tpSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let mgr = L2tpSessionManager::new();
        let session = mgr.create_session("tun1", "user1").await.unwrap();
        assert_eq!(session.username, "user1");
        assert!(session.enabled);

        let sessions = mgr.list_sessions("tun1").await;
        assert_eq!(sessions.len(), 1);

        mgr.end_session("tun1", session.session_id)
            .await
            .unwrap();
        let sessions = mgr.list_sessions("tun1").await;
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_update_stats() {
        let mgr = L2tpSessionManager::new();
        let session = mgr.create_session("tun1", "user1").await.unwrap();
        mgr.update_stats("tun1", session.session_id, 1000, 2000).await;
        let sessions = mgr.list_sessions("tun1").await;
        assert_eq!(sessions[0].rx_bytes, 1000);
        assert_eq!(sessions[0].tx_bytes, 2000);
    }
}
