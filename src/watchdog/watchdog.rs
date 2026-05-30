use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogConfig {
    pub enabled: bool,
    pub interval_secs: u32,
    pub reboot_on_failure: bool,
    pub ping_target: Option<String>,
    pub ping_interval_secs: u32,
    pub ping_fail_count: u32,
}

impl Default for WatchdogConfig {
    fn default() -> Self { Self { enabled: false, interval_secs: 60, reboot_on_failure: false, ping_target: None, ping_interval_secs: 10, ping_fail_count: 3 } }
}

pub struct WatchdogManager { config: Mutex<WatchdogConfig> }

impl WatchdogManager {
    pub fn new() -> Self { Self { config: Mutex::new(WatchdogConfig::default()) } }
    pub fn get_config(&self) -> WatchdogConfig { self.config.lock().unwrap().clone() }
    pub fn set_config(&self, c: WatchdogConfig) { *self.config.lock().unwrap() = c; }
}

impl Default for WatchdogManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests { use super::*; #[test] fn test_watchdog() { let m = WatchdogManager::new(); assert!(!m.get_config().enabled); } }
