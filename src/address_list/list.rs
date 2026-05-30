use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AddressListPolicy {
    Allow,
    Drop,
    Reject,
}

impl std::fmt::Display for AddressListPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressListEntry {
    pub id: u64,
    pub name: String,
    pub address: IpAddr,
    pub prefix: u8,
    pub policy: AddressListPolicy,
    pub timeout: Option<Duration>,
    pub created_at: u64,
    pub source: String,
}

impl AddressListEntry {
    pub fn matches(&self, ip: IpAddr) -> bool {
        match (ip, self.address) {
            (IpAddr::V4(ip), IpAddr::V4(addr)) => {
                let mask = if self.prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - self.prefix)
                };
                (u32::from(ip) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(addr)) => {
                let mask = if self.prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - self.prefix)
                };
                (u128::from(ip) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(timeout) = self.timeout {
            let elapsed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            elapsed > self.created_at + timeout.as_secs()
        } else {
            false
        }
    }
}

static NEXT_ADDR_LIST_ID: AtomicU64 = AtomicU64::new(1);

pub struct AddressList {
    entries: HashMap<u64, AddressListEntry>,
    lists: HashMap<String, Vec<u64>>,
}

impl AddressList {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lists: HashMap::new(),
        }
    }

    pub fn add(
        &mut self,
        name: &str,
        address: IpAddr,
        prefix: u8,
        policy: AddressListPolicy,
        timeout: Option<Duration>,
        source: &str,
    ) -> Result<AddressListEntry> {
        if name.is_empty() {
            bail!("address list name cannot be empty");
        }
        if prefix > 128 {
            bail!("prefix must be <= 128");
        }

        let id = NEXT_ADDR_LIST_ID.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = AddressListEntry {
            id,
            name: name.to_string(),
            address,
            prefix,
            policy,
            timeout,
            created_at: now,
            source: source.to_string(),
        };

        self.entries.insert(id, entry.clone());
        self.lists
            .entry(name.to_string())
            .or_default()
            .push(id);

        Ok(entry)
    }

    pub fn remove(&mut self, id: u64) -> Result<()> {
        let entry = self
            .entries
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("address list entry {id} not found"))?;
        if let Some(ids) = self.lists.get_mut(&entry.name) {
            ids.retain(|&i| i != id);
            if ids.is_empty() {
                self.lists.remove(&entry.name);
            }
        }
        Ok(())
    }

    pub fn get(&self, id: u64) -> Result<&AddressListEntry> {
        self.entries
            .get(&id)
            .ok_or_else(|| anyhow::anyhow!("address list entry {id} not found"))
    }

    pub fn list(&self, name: &str) -> Vec<&AddressListEntry> {
        self.lists
            .get(name)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| {
                        let entry = self.entries.get(id)?;
                        if entry.is_expired() { None } else { Some(entry) }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.lists.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn match_ip(&self, ip: IpAddr) -> Option<&AddressListEntry> {
        for ids in self.lists.values() {
            for id in ids {
                if let Some(entry) = self.entries.get(id) {
                    if !entry.is_expired() && entry.matches(ip) {
                        return Some(entry);
                    }
                }
            }
        }
        None
    }

    pub fn flush(&mut self, name: &str) {
        if let Some(ids) = self.lists.remove(name) {
            for id in ids {
                self.entries.remove(&id);
            }
        }
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<u64> = self
            .entries
            .values()
            .filter(|e| e.is_expired())
            .map(|e| e.id)
            .collect();
        let count = expired.len();
        for id in expired {
            let _ = self.remove(id);
        }
        count
    }
}

impl Default for AddressList {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AddressListManager {
    list: std::sync::Mutex<AddressList>,
}

impl AddressListManager {
    pub fn new() -> Self {
        Self {
            list: std::sync::Mutex::new(AddressList::new()),
        }
    }

    pub fn add(
        &self,
        name: &str,
        address: IpAddr,
        prefix: u8,
        policy: AddressListPolicy,
        timeout: Option<Duration>,
        source: &str,
    ) -> Result<AddressListEntry> {
        self.list
            .lock()
            .unwrap()
            .add(name, address, prefix, policy, timeout, source)
    }

    pub fn remove(&self, id: u64) -> Result<()> {
        self.list.lock().unwrap().remove(id)
    }

    pub fn get(&self, id: u64) -> Result<AddressListEntry> {
        self.list.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self, name: &str) -> Vec<AddressListEntry> {
        self.list
            .lock()
            .unwrap()
            .list(name)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn list_names(&self) -> Vec<String> {
        self.list.lock().unwrap().list_names()
    }

    pub fn match_ip(&self, ip: IpAddr) -> Option<AddressListEntry> {
        self.list.lock().unwrap().match_ip(ip).cloned()
    }

    pub fn flush(&self, name: &str) {
        self.list.lock().unwrap().flush(name);
    }

    pub fn cleanup_expired(&self) -> usize {
        self.list.lock().unwrap().cleanup_expired()
    }
}

impl Default for AddressListManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let mut al = AddressList::new();
        let entry = al
            .add(
                "blacklist",
                "192.168.1.0".parse().unwrap(),
                24,
                AddressListPolicy::Drop,
                None,
                "manual",
            )
            .unwrap();
        assert_eq!(entry.name, "blacklist");
        assert_eq!(al.get(entry.id).unwrap().name, "blacklist");
    }

    #[test]
    fn test_ipv4_matching() {
        let mut al = AddressList::new();
        al.add(
            "blocked",
            "10.0.0.0".parse().unwrap(),
            8,
            AddressListPolicy::Drop,
            None,
            "test",
        )
        .unwrap();
        assert!(al
            .match_ip("10.0.1.50".parse().unwrap())
            .is_some());
        assert!(al
            .match_ip("192.168.1.1".parse().unwrap())
            .is_none());
    }

    #[test]
    fn test_remove() {
        let mut al = AddressList::new();
        let entry = al
            .add(
                "test",
                "1.2.3.4".parse().unwrap(),
                32,
                AddressListPolicy::Allow,
                None,
                "manual",
            )
            .unwrap();
        assert!(al.remove(entry.id).is_ok());
        assert!(al.get(entry.id).is_err());
    }

    #[test]
    fn test_flush() {
        let mut al = AddressList::new();
        al.add(
            "list1",
            "1.1.1.1".parse().unwrap(),
            32,
            AddressListPolicy::Allow,
            None,
            "test",
        )
        .unwrap();
        al.add(
            "list1",
            "2.2.2.2".parse().unwrap(),
            32,
            AddressListPolicy::Allow,
            None,
            "test",
        )
        .unwrap();
        assert_eq!(al.list("list1").len(), 2);
        al.flush("list1");
        assert_eq!(al.list("list1").len(), 0);
    }

    #[test]
    fn test_expiry() {
        let mut al = AddressList::new();
        al.add(
            "temp",
            "1.1.1.1".parse().unwrap(),
            32,
            AddressListPolicy::Drop,
            Some(Duration::from_secs(0)),
            "test",
        )
        .unwrap();
        assert_eq!(al.cleanup_expired(), 1);
    }

    #[test]
    fn test_manager_thread_safe() {
        let mgr = AddressListManager::new();
        mgr.add(
            "test",
            "10.0.0.1".parse().unwrap(),
            32,
            AddressListPolicy::Allow,
            None,
            "manual",
        )
        .unwrap();
        assert_eq!(mgr.list_names().len(), 1);
        assert!(mgr.match_ip("10.0.0.1".parse().unwrap()).is_some());
    }
}
