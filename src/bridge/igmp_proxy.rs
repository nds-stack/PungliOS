use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgmpProxyConfig {
    pub enabled: bool,
    pub upstream: String,
    pub downstream: Vec<String>,
    pub igmp_version: u8,
}

pub struct IgmpProxyManager { config: Mutex<IgmpProxyConfig> }

impl IgmpProxyManager {
    pub fn new() -> Self { Self { config: Mutex::new(IgmpProxyConfig { enabled: false, upstream: String::new(), downstream: vec![], igmp_version: 3 }) } }
    pub fn get_config(&self) -> IgmpProxyConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: IgmpProxyConfig) { *self.config.lock().unwrap() = c; }
}

impl Default for IgmpProxyManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_igmp_proxy() { let m = IgmpProxyManager::new(); assert!(!m.get_config().enabled); }
}
