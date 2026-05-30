use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogEntry {
    pub timestamp: u64,
    pub facility: String,
    pub severity: String,
    pub tag: String,
    pub message: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub remote_server: Option<String>,
    pub remote_port: Option<u16>,
    pub local_storage: bool,
    pub max_entries: usize,
}

impl Default for SyslogConfig {
    fn default() -> Self { Self { enabled: false, listen_port: 514, remote_server: None, remote_port: None, local_storage: true, max_entries: 10000 } }
}

pub struct SyslogServer {
    config: Mutex<SyslogConfig>,
    entries: Mutex<Vec<SyslogEntry>>,
}

impl SyslogServer {
    pub fn new() -> Self { Self { config: Mutex::new(SyslogConfig::default()), entries: Mutex::new(Vec::new()) } }
    pub fn get_config(&self) -> SyslogConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: SyslogConfig) { *self.config.lock().unwrap() = c; }
    pub fn add_entry(&self, entry: SyslogEntry) {
        let mut e = self.entries.lock().unwrap();
        e.push(entry);
        let max = self.config.lock().unwrap().max_entries;
        let len = e.len();
        if len > max { e.drain(0..len - max); }
    }
    pub fn get_entries(&self) -> Vec<SyslogEntry> { self.entries.lock().unwrap().clone() }
    pub fn clear(&self) { self.entries.lock().unwrap().clear(); }
}

impl Default for SyslogServer { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_syslog() {
        let s = SyslogServer::new();
        s.add_entry(SyslogEntry { timestamp: 0, facility: "daemon".into(), severity: "info".into(), tag: "punglios[123]".into(), message: "started".into(), source: "127.0.0.1".into() });
        assert_eq!(s.get_entries().len(), 1);
    }
}
