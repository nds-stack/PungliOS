use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ─── Prefix List ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrefixListAction {
    Permit,
    Deny,
}

impl std::fmt::Display for PrefixListAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permit => write!(f, "permit"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrefixListEntry {
    pub name: String,
    pub seq: u32,
    pub action: PrefixListAction,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    pub description: Option<String>,
}

impl PrefixListEntry {
    pub fn matches(&self, cidr: &str, prefix_len: u8) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }
        let cidr_prefix: u8 = parts[1].parse().unwrap_or(0);
        if cidr_prefix != prefix_len {
            return false;
        }
        self.prefix == cidr
    }
}

// ─── AS Path Filter ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AsPathMatch {
    Exact(Vec<u32>),
    Regex(String),
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsPathFilter {
    pub name: String,
    pub match_type: AsPathMatch,
    pub action: PrefixListAction,
}

impl AsPathFilter {
    pub fn matches(&self, as_path: &[u32]) -> bool {
        match &self.match_type {
            AsPathMatch::Exact(path) => as_path == path.as_slice(),
            AsPathMatch::Regex(_) => {
                let path_str = as_path
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                let pattern = match &self.match_type {
                    AsPathMatch::Regex(r) => r,
                    _ => return false,
                };
                path_str.contains(pattern)
            }
            AsPathMatch::Any => true,
        }
    }
}

// ─── Route Map ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SetAction {
    LocalPref(u32),
    Metric(u32),
    Community(String),
    AsPathPrepend(u32),
    NextHop(IpAddr),
    Tag(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteMapEntry {
    pub name: String,
    pub seq: u32,
    pub action: PrefixListAction,
    pub match_prefix_list: Option<String>,
    pub match_as_path: Option<String>,
    pub match_community: Option<String>,
    pub match_metric: Option<u32>,
    pub set_actions: Vec<SetAction>,
    pub description: Option<String>,
}

// ─── Manager ────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

pub struct RouteFilterManager {
    prefix_lists: Mutex<HashMap<String, Vec<PrefixListEntry>>>,
    as_path_filters: Mutex<HashMap<String, AsPathFilter>>,
    route_maps: Mutex<HashMap<String, Vec<RouteMapEntry>>>,
}

impl RouteFilterManager {
    pub fn new() -> Self {
        Self {
            prefix_lists: Mutex::new(HashMap::new()),
            as_path_filters: Mutex::new(HashMap::new()),
            route_maps: Mutex::new(HashMap::new()),
        }
    }

    // Prefix List
    pub fn add_prefix_list_entry(&self, entry: PrefixListEntry) -> anyhow::Result<()> {
        if entry.name.is_empty() {
            anyhow::bail!("prefix list name cannot be empty");
        }
        let mut pl = self.prefix_lists.lock().unwrap();
        pl.entry(entry.name.clone()).or_default().push(entry);
        Ok(())
    }

    pub fn remove_prefix_list(&self, name: &str) -> anyhow::Result<()> {
        let mut pl = self.prefix_lists.lock().unwrap();
        pl.remove(name);
        Ok(())
    }

    pub fn list_prefix_lists(&self) -> Vec<String> {
        self.prefix_lists.lock().unwrap().keys().cloned().collect()
    }

    pub fn get_prefix_list(&self, name: &str) -> Vec<PrefixListEntry> {
        self.prefix_lists
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    // AS Path
    pub fn add_as_path_filter(&self, filter: AsPathFilter) -> anyhow::Result<()> {
        if filter.name.is_empty() {
            anyhow::bail!("AS path filter name cannot be empty");
        }
        let mut af = self.as_path_filters.lock().unwrap();
        af.insert(filter.name.clone(), filter);
        Ok(())
    }

    pub fn remove_as_path_filter(&self, name: &str) -> anyhow::Result<()> {
        let mut af = self.as_path_filters.lock().unwrap();
        af.remove(name);
        Ok(())
    }

    pub fn list_as_path_filters(&self) -> Vec<AsPathFilter> {
        self.as_path_filters
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    // Route Map
    pub fn add_route_map_entry(&self, entry: RouteMapEntry) -> anyhow::Result<()> {
        if entry.name.is_empty() {
            anyhow::bail!("route-map name cannot be empty");
        }
        let mut rm = self.route_maps.lock().unwrap();
        rm.entry(entry.name.clone()).or_default().push(entry);
        Ok(())
    }

    pub fn remove_route_map(&self, name: &str) -> anyhow::Result<()> {
        let mut rm = self.route_maps.lock().unwrap();
        rm.remove(name);
        Ok(())
    }

    pub fn list_route_maps(&self) -> Vec<String> {
        self.route_maps.lock().unwrap().keys().cloned().collect()
    }

    pub fn get_route_map(&self, name: &str) -> Vec<RouteMapEntry> {
        self.route_maps
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }
}

impl Default for RouteFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_list_matches() {
        let entry = PrefixListEntry {
            name: "block-rfc1918".into(),
            seq: 10,
            action: PrefixListAction::Deny,
            prefix: "10.0.0.0/8".into(),
            ge: None,
            le: None,
            description: None,
        };
        assert!(entry.matches("10.0.0.0/8", 8));
        assert!(!entry.matches("192.168.0.0/16", 16));
    }

    #[test]
    fn test_as_path_filter() {
        let filter = AsPathFilter {
            name: "transit-only".into(),
            match_type: AsPathMatch::Exact(vec![64512, 64513]),
            action: PrefixListAction::Permit,
        };
        assert!(filter.matches(&[64512, 64513]));
        assert!(!filter.matches(&[64512]));
    }

    #[test]
    fn test_manager_roundtrip() {
        let mgr = RouteFilterManager::new();
        mgr.add_prefix_list_entry(PrefixListEntry {
            name: "test".into(),
            seq: 10,
            action: PrefixListAction::Permit,
            prefix: "0.0.0.0/0".into(),
            ge: None,
            le: None,
            description: None,
        })
        .unwrap();
        assert_eq!(mgr.list_prefix_lists(), vec!["test"]);
        assert_eq!(mgr.get_prefix_list("test").len(), 1);
    }

    #[test]
    fn test_route_map() {
        let mgr = RouteFilterManager::new();
        mgr.add_route_map_entry(RouteMapEntry {
            name: "set-local-pref".into(),
            seq: 10,
            action: PrefixListAction::Permit,
            match_prefix_list: Some("default".into()),
            match_as_path: None,
            match_community: None,
            match_metric: None,
            set_actions: vec![SetAction::LocalPref(200)],
            description: None,
        })
        .unwrap();
        assert_eq!(mgr.list_route_maps().len(), 1);
        let entries = mgr.get_route_map("set-local-pref");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].set_actions[0], SetAction::LocalPref(200)));
    }
}
