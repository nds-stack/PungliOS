use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer7Pattern {
    pub name: String,
    pub pattern: String,
    pub description: Option<String>,
    pub enabled: bool,
}

impl Layer7Pattern {
    pub fn matches(&self, data: &[u8]) -> bool {
        if !self.enabled || self.pattern.is_empty() {
            return false;
        }
        // Convert data to string lossily for regex matching
        let text = String::from_utf8_lossy(data);

        // Try exact substring match first (fast path)
        if let Ok(re) = regex::Regex::new(&self.pattern) {
            re.is_match(&text)
        } else {
            // Fallback to simple substring match
            text.contains(&self.pattern)
        }
    }
}

pub struct Layer7Manager {
    patterns: Mutex<HashMap<String, Layer7Pattern>>,
}

impl Layer7Manager {
    pub fn new() -> Self {
        Self {
            patterns: Mutex::new(HashMap::new()),
        }
    }

    pub fn add(&self, pattern: Layer7Pattern) -> anyhow::Result<()> {
        if pattern.name.is_empty() {
            anyhow::bail!("pattern name cannot be empty");
        }
        if pattern.pattern.is_empty() {
            anyhow::bail!("pattern string cannot be empty");
        }
        // Validate regex
        if regex::Regex::new(&pattern.pattern).is_err() {
            anyhow::bail!("invalid regex pattern: {}", pattern.pattern);
        }
        let mut patterns = self.patterns.lock().unwrap();
        if patterns.contains_key(&pattern.name) {
            anyhow::bail!("pattern '{}' already exists", pattern.name);
        }
        patterns.insert(pattern.name.clone(), pattern);
        Ok(())
    }

    pub fn remove(&self, name: &str) -> anyhow::Result<()> {
        let mut patterns = self.patterns.lock().unwrap();
        patterns.remove(name);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<Layer7Pattern> {
        self.patterns.lock().unwrap().get(name).cloned()
    }

    pub fn list(&self) -> Vec<Layer7Pattern> {
        let mut patterns: Vec<_> = self.patterns.lock().unwrap().values().cloned().collect();
        patterns.sort_by_key(|p| p.name.clone());
        patterns
    }

    pub fn match_against(&self, data: &[u8]) -> Vec<Layer7Pattern> {
        let patterns = self.patterns.lock().unwrap();
        patterns
            .values()
            .filter(|p| p.matches(data))
            .cloned()
            .collect()
    }

    pub fn match_first(&self, data: &[u8]) -> Option<Layer7Pattern> {
        let patterns = self.patterns.lock().unwrap();
        patterns.values().find(|p| p.matches(data)).cloned()
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> anyhow::Result<()> {
        let mut patterns = self.patterns.lock().unwrap();
        if let Some(p) = patterns.get_mut(name) {
            p.enabled = enabled;
            Ok(())
        } else {
            anyhow::bail!("pattern '{name}' not found")
        }
    }
}

impl Default for Layer7Manager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_pattern() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "http".into(),
            pattern: r"GET /.* HTTP/1\.\d".into(),
            description: Some("HTTP GET requests".into()),
            enabled: true,
        })
        .unwrap();
        assert_eq!(mgr.list().len(), 1);
    }

    #[test]
    fn test_http_matching() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "http".into(),
            pattern: r"GET /.* HTTP/1\.\d".into(),
            description: None,
            enabled: true,
        })
        .unwrap();
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
        assert!(mgr.match_first(data).is_some());
    }

    #[test]
    fn test_https_not_matched() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "http".into(),
            pattern: r"GET /.* HTTP/1\.\d".into(),
            description: None,
            enabled: true,
        })
        .unwrap();
        // HTTPS encrypted - should not match
        let data = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03";
        assert!(mgr.match_first(data).is_none());
    }

    #[test]
    fn test_dns_matching() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "dns".into(),
            pattern: r"[\x00-\x20]*\x00\x01\x00\x00\x00\x00\x00\x01".into(),
            description: Some("DNS query".into()),
            enabled: true,
        })
        .unwrap();
        // Simple DNS query header
        let data = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01";
        assert!(mgr.match_first(data).is_some());
    }

    #[test]
    fn test_invalid_regex_rejected() {
        let mgr = Layer7Manager::new();
        assert!(mgr
            .add(Layer7Pattern {
                name: "bad".into(),
                pattern: r"[invalid".into(),
                description: None,
                enabled: true,
            })
            .is_err());
    }

    #[test]
    fn test_pattern_disabled() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "ssh".into(),
            pattern: r"SSH-\d+\.\d+".into(),
            description: None,
            enabled: false,
        })
        .unwrap();
        let data = b"SSH-2.0-OpenSSH_8.9p1";
        assert!(mgr.match_first(data).is_none());
    }

    #[test]
    fn test_substring_fallback() {
        let mgr = Layer7Manager::new();
        mgr.add(Layer7Pattern {
            name: "bittorrent".into(),
            pattern: "BitTorrent".into(),
            description: None,
            enabled: true,
        })
        .unwrap();
        let data = b"d1:md11:BitTorrent protocol";
        assert!(mgr.match_first(data).is_some());
    }
}
