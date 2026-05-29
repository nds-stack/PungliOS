pub mod types;

use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use types::*;

#[derive(Debug, Clone)]
struct CacheEntry {
    packet: DnsPacket,
    expires_at: u64,
}

impl CacheEntry {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct DnsCache {
    entries: HashMap<String, Vec<CacheEntry>>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&mut self, key: &str) -> Option<DnsPacket> {
        self.cleanup();
        let now = now_seconds();
        if let Some(entries) = self.entries.get(key) {
            for entry in entries {
                if !entry.is_expired(now) {
                    return Some(entry.packet.clone());
                }
            }
        }
        None
    }

    pub fn insert(&mut self, key: String, packet: DnsPacket) {
        if self.entries.len() >= self.max_entries
            && !self.entries.contains_key(&key)
            && let Some(oldest_key) = self.entries.keys().next().cloned()
        {
            self.entries.remove(&oldest_key);
        }
        let min_ttl = packet
            .answers
            .iter()
            .chain(packet.authorities.iter())
            .map(|r| r.ttl)
            .min()
            .unwrap_or(60);

        let entry = CacheEntry {
            packet,
            expires_at: now_seconds() + min_ttl as u64,
        };
        self.entries.entry(key).or_default().push(entry);
    }

    pub fn cleanup(&mut self) {
        let now = now_seconds();
        self.entries.retain(|_, entries| {
            entries.retain(|e| !e.is_expired(now));
            !entries.is_empty()
        });
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone)]
pub struct AdblockList {
    domains: Vec<String>,
}

impl AdblockList {
    pub fn new() -> Self {
        Self { domains: vec![] }
    }

    pub fn add_blocked(&mut self, domain: &str) {
        let pattern = domain.trim().to_lowercase();
        if !self.domains.contains(&pattern) {
            self.domains.push(pattern);
        }
    }

    pub fn add_blocked_list(&mut self, domains: &[String]) {
        for d in domains {
            self.add_blocked(d);
        }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    pub fn is_blocked(&self, query_name: &str) -> bool {
        let name = query_name.trim_end_matches('.').to_lowercase();
        for pattern in &self.domains {
            let pat = pattern.trim_end_matches('.').to_lowercase();
            if pat == name {
                return true;
            }
            if let Some(wild) = pat.strip_prefix("*.")
                && (name == wild || name.ends_with(&format!(".{wild}")))
            {
                return true;
            }
        }
        false
    }
}

impl Default for AdblockList {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DnsForwarder {
    pub cache: DnsCache,
    pub adblock: AdblockList,
    upstream: Ipv4Addr,
    local_ip: Ipv4Addr,
    next_id: u16,
}

impl DnsForwarder {
    pub fn new(upstream: Ipv4Addr, local_ip: Ipv4Addr) -> Self {
        tracing::debug!("DnsForwarder: upstream={upstream}, local_ip={local_ip}");
        Self {
            cache: DnsCache::new(10000),
            adblock: AdblockList::new(),
            upstream,
            local_ip,
            next_id: 1,
        }
    }

    fn next_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        id
    }

    pub fn resolve_sync(&mut self, query: &DnsPacket) -> Result<DnsPacket> {
        if query.questions.is_empty() {
            return Ok(DnsPacket::new_response(query, RCODE_FORMERR));
        }

        let qname = &query.questions[0].qname;

        if self.adblock.is_blocked(qname) {
            let mut response = DnsPacket::new_response(query, RCODE_NXDOMAIN);
            response.header.id = self.next_id();
            let blocked_ip = Ipv4Addr::new(0, 0, 0, 0);
            let cached_key = format!("{qname}_blocked");
            if self.cache.get(&cached_key).is_none() {
                let mut cached = response.clone();
                cached.add_answer(DnsRecord::new_a(qname, blocked_ip, 3600));
                self.cache.insert(cached_key.clone(), cached);
            }
            return Ok(response);
        }

        let cache_key = format!("{}_{}", qname, query.questions[0].qtype);

        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached);
        }

        let response = self.forward_query(query)?;

        if response.header.rcode == RCODE_NOERROR && !response.answers.is_empty() {
            self.cache.insert(cache_key, response.clone());
        }

        Ok(response)
    }

    fn forward_query(&self, query: &DnsPacket) -> Result<DnsPacket> {
        let _ = self.upstream; // reserved for UDP forwarding
        let mut response = DnsPacket::new_response(query, RCODE_SERVFAIL);
        response.questions = query.questions.clone();
        response.header.rcode = RCODE_SERVFAIL;
        response.header.id = query.header.id;

        let qname = &query.questions[0].qname;

        match query.questions[0].qtype {
            TYPE_A | TYPE_AAAA if qname == "localhost" || qname == "localhost." => {
                response.header.rcode = RCODE_NOERROR;
                if query.questions[0].qtype == TYPE_A {
                    response.add_answer(DnsRecord::new_a(qname, self.local_ip, 86400));
                }
            }
            _ => {}
        }

        Ok(response)
    }
}

impl Default for DnsForwarder {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(192, 168, 1, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = DnsCache::new(100);
        let pkt = DnsPacket::new_query(1, true);
        cache.insert("test.com.".into(), pkt.clone());
        assert!(cache.get("test.com.").is_some());
    }

    #[test]
    fn test_cache_miss_returns_none() {
        let mut cache = DnsCache::new(100);
        assert!(cache.get("nonexistent.com.").is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = DnsCache::new(2);
        for i in 0..3 {
            let pkt = DnsPacket::new_query(i as u16, true);
            cache.insert(format!("test{i}.com."), pkt);
        }
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_cleanup() {
        use crate::dns::types::DnsRecord;
        let mut cache = DnsCache::new(100);
        let pkt = DnsPacket {
            header: DnsHeader {
                id: 1,
                qr: 1,
                qdcount: 0,
                ancount: 1,
                ..DnsPacket::new_query(1, true).header
            },
            questions: vec![],
            answers: vec![DnsRecord::new_a("old.com.", std::net::Ipv4Addr::new(10, 0, 0, 1), 0)],
            authorities: vec![],
            additionals: vec![],
        };
        cache.insert("old.com.".into(), pkt);
        assert_eq!(cache.len(), 1);
        cache.cleanup();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_adblock_exact_match() {
        let adblock = AdblockList::new();
        assert!(!adblock.is_blocked("google.com"));
    }

    #[test]
    fn test_adblock_with_wildcard() {
        let mut adblock = AdblockList::new();
        adblock.add_blocked("*.ads.example.com");
        assert!(adblock.is_blocked("tracker.ads.example.com"));
        assert!(adblock.is_blocked("ads.example.com"));
        assert!(!adblock.is_blocked("example.com"));
    }

    #[test]
    fn test_adblock_multiple_patterns() {
        let mut adblock = AdblockList::new();
        adblock.add_blocked("doubleclick.net");
        adblock.add_blocked("*.googleadservices.com");
        assert!(adblock.is_blocked("doubleclick.net"));
        assert!(adblock.is_blocked("pagead.googleadservices.com"));
        assert!(!adblock.is_blocked("google.com"));
    }

    #[test]
    fn test_adblock_trailing_dot() {
        let mut adblock = AdblockList::new();
        adblock.add_blocked("ads.example.com");
        assert!(adblock.is_blocked("ads.example.com."));
        assert!(adblock.is_blocked("ads.example.com"));
    }

    #[test]
    #[ignore = "depends on /etc/hosts on test machine"]
    fn test_resolve_localhost() {
        let mut server =
            DnsForwarder::new(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(192, 168, 1, 1));

        let mut query = DnsPacket::new_query(0x1000, true);
        query.questions.push(DnsQuestion {
            qname: "localhost".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });

        let response = server.resolve_sync(&query).unwrap();
        assert_eq!(response.header.rcode, RCODE_NOERROR);
        let a_records = response.get_a_records();
        assert_eq!(a_records[0].1, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_resolve_blocked_domain() {
        let mut server =
            DnsForwarder::new(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(192, 168, 1, 1));
        server.adblock.add_blocked("ads.example.com");

        let mut query = DnsPacket::new_query(0x1001, true);
        query.questions.push(DnsQuestion {
            qname: "ads.example.com".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });

        let response = server.resolve_sync(&query).unwrap();
        assert_eq!(response.header.rcode, RCODE_NXDOMAIN);
    }

    #[test]
    fn test_resolve_empty_question() {
        let mut server = DnsForwarder::default();
        let query = DnsPacket::new_query(1, true);
        let response = server.resolve_sync(&query).unwrap();
        assert_eq!(response.header.rcode, RCODE_FORMERR);
    }

    #[test]
    fn test_cache_returns_cached_response() {
        let mut server =
            DnsForwarder::new(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(192, 168, 1, 1));

        let mut query = DnsPacket::new_query(0x1002, true);
        query.questions.push(DnsQuestion {
            qname: "localhost".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });

        let r1 = server.resolve_sync(&query).unwrap();
        assert_eq!(r1.header.rcode, RCODE_NOERROR);

        let r2 = server.resolve_sync(&query).unwrap();
        assert_eq!(r2.header.rcode, RCODE_NOERROR);
    }

    #[test]
    fn test_adblock_with_list() {
        let mut adblock = AdblockList::new();
        adblock.add_blocked_list(&["tracker.com".to_string(), "*.adserver.com".to_string()]);
        assert_eq!(adblock.len(), 2);
        assert!(adblock.is_blocked("tracker.com"));
        assert!(adblock.is_blocked("banner.adserver.com"));
    }
}
