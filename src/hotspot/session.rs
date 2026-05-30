use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Unauthorized,
    Authorizing,
    Active,
    IdleTimeout,
    LoggedOut,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Authorizing => write!(f, "authorizing"),
            Self::Active => write!(f, "active"),
            Self::IdleTimeout => write!(f, "idle-timeout"),
            Self::LoggedOut => write!(f, "logged-out"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotSession {
    pub id: u64,
    pub username: String,
    pub password: String,
    pub ip_address: IpAddr,
    pub mac_address: String,
    pub state: SessionState,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub started_at: u64,
    pub last_active: u64,
    pub idle_timeout_secs: u64,
    pub uptime_secs: u64,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub struct SessionManager {
    sessions: Mutex<HashMap<u64, HotspotSession>>,
    by_ip: Mutex<HashMap<IpAddr, u64>>,
    by_mac: Mutex<HashMap<String, u64>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
            by_mac: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, username: &str, password: &str, ip: IpAddr, mac: &str) -> Result<HotspotSession> {
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.by_ip.lock().unwrap().contains_key(&ip) {
            anyhow::bail!("IP {ip} already has an active session");
        }

        let session = HotspotSession {
            id,
            username: username.to_string(),
            password: password.to_string(),
            ip_address: ip,
            mac_address: mac.to_string(),
            state: SessionState::Unauthorized,
            bytes_in: 0,
            bytes_out: 0,
            started_at: now,
            last_active: now,
            idle_timeout_secs: 600,
            uptime_secs: 0,
        };

        self.sessions.lock().unwrap().insert(id, session.clone());
        self.by_ip.lock().unwrap().insert(ip, id);
        self.by_mac.lock().unwrap().insert(mac.to_string(), id);
        Ok(session)
    }

    pub fn authorize(&self, id: u64) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {id} not found"))?;
        session.state = SessionState::Active;
        Ok(())
    }

    pub fn logout(&self, id: u64) -> Result<()> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("session {id} not found"))?;
        session.state = SessionState::LoggedOut;
        Ok(())
    }

    pub fn get(&self, id: u64) -> Option<HotspotSession> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    pub fn get_by_ip(&self, ip: IpAddr) -> Option<HotspotSession> {
        let by_ip = self.by_ip.lock().unwrap();
        let id = by_ip.get(&ip)?;
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<HotspotSession> {
        let mut sessions: Vec<_> = self.sessions.lock().unwrap().values().cloned().collect();
        sessions.sort_by_key(|s| s.id);
        sessions
    }

    pub fn list_active(&self) -> Vec<HotspotSession> {
        self.list()
            .into_iter()
            .filter(|s| s.state == SessionState::Active)
            .collect()
    }

    pub fn update_activity(&self, id: u64, bytes_in: u64, bytes_out: u64) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&id) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            session.bytes_in += bytes_in;
            session.bytes_out += bytes_out;
            session.last_active = now;
            session.uptime_secs = now.saturating_sub(session.started_at);
        }
    }

    pub fn check_idle_timeouts(&self) -> Vec<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut timed_out = Vec::new();
        let mut sessions = self.sessions.lock().unwrap();
        for (id, session) in sessions.iter_mut() {
            if session.state == SessionState::Active {
                let idle = now.saturating_sub(session.last_active);
                if idle > session.idle_timeout_secs {
                    session.state = SessionState::IdleTimeout;
                    timed_out.push(*id);
                }
            }
        }
        timed_out
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let mgr = SessionManager::new();
        let session = mgr
            .create("user1", "pass123", "10.0.0.100".parse().unwrap(), "aa:bb:cc:dd:ee:01")
            .unwrap();
        assert_eq!(session.state, SessionState::Unauthorized);

        mgr.authorize(session.id).unwrap();
        let s = mgr.get(session.id).unwrap();
        assert_eq!(s.state, SessionState::Active);

        mgr.logout(session.id).unwrap();
        let s = mgr.get(session.id).unwrap();
        assert_eq!(s.state, SessionState::LoggedOut);
    }

    #[test]
    fn test_duplicate_ip_rejected() {
        let mgr = SessionManager::new();
        mgr.create("u1", "p1", "10.0.0.1".parse().unwrap(), "aa:bb:cc:dd:ee:01")
            .unwrap();
        assert!(mgr
            .create("u2", "p2", "10.0.0.1".parse().unwrap(), "aa:bb:cc:dd:ee:02")
            .is_err());
    }

    #[test]
    fn test_get_by_ip() {
        let mgr = SessionManager::new();
        let ip: IpAddr = "10.0.0.50".parse().unwrap();
        mgr.create("user", "pass", ip, "aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert!(mgr.get_by_ip(ip).is_some());
    }

    #[test]
    fn test_update_activity() {
        let mgr = SessionManager::new();
        let session = mgr
            .create("u", "p", "10.0.0.10".parse().unwrap(), "aa:bb:cc:dd:ee:10")
            .unwrap();
        mgr.update_activity(session.id, 1000, 2000);
        let s = mgr.get(session.id).unwrap();
        assert_eq!(s.bytes_in, 1000);
        assert_eq!(s.bytes_out, 2000);
    }
}
