use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgmpGroup {
    pub group: IpAddr,
    pub interface: String,
    pub members: Vec<String>,
    pub last_reporter: Option<IpAddr>,
    pub expires_secs: u64,
}

pub struct IgmpSnooping {
    groups: Mutex<Vec<IgmpGroup>>,
    enabled: Mutex<bool>,
}

impl IgmpSnooping {
    pub fn new() -> Self { Self { groups: Mutex::new(Vec::new()), enabled: Mutex::new(false) } }
    pub fn set_enabled(&self, val: bool) { *self.enabled.lock().unwrap() = val; }
    pub fn is_enabled(&self) -> bool { *self.enabled.lock().unwrap() }
    pub fn add_group(&self, group: IgmpGroup) { self.groups.lock().unwrap().push(group); }
    pub fn remove_group(&self, group: &IpAddr) { self.groups.lock().unwrap().retain(|g| g.group != *group); }
    pub fn list_groups(&self) -> Vec<IgmpGroup> { self.groups.lock().unwrap().clone() }
    pub fn count(&self) -> usize { self.groups.lock().unwrap().len() }
}

impl Default for IgmpSnooping { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_igmp() {
        let igmp = IgmpSnooping::new();
        igmp.set_enabled(true);
        assert!(igmp.is_enabled());
        igmp.add_group(IgmpGroup {
            group: "239.255.255.250".parse().unwrap(),
            interface: "br0".into(), members: vec!["aa:bb:cc:dd:ee:ff".into()],
            last_reporter: None, expires_secs: 260,
        });
        assert_eq!(igmp.count(), 1);
    }
}
