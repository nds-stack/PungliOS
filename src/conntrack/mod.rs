pub mod fast_track;
pub mod tuning;

use crate::traits::{ConntrackEntry, NetlinkConntrack};
use anyhow::{Result, bail};
use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

pub const MAX_CONNTRACK_DEFAULT: u32 = 262_144;
pub const BUCKETS_DEFAULT: u32 = 65_536;

pub struct ConntrackManager<T: NetlinkConntrack> {
    backend: T,
    max: u32,
    buckets: u32,
}

impl<T: NetlinkConntrack + fmt::Debug> fmt::Debug for ConntrackManager<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConntrackManager")
            .field("backend", &self.backend)
            .field("max", &self.max)
            .field("buckets", &self.buckets)
            .finish()
    }
}

impl<T: NetlinkConntrack> ConntrackManager<T> {
    pub fn new(backend: T) -> Self {
        Self {
            backend,
            max: MAX_CONNTRACK_DEFAULT,
            buckets: BUCKETS_DEFAULT,
        }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub fn max(&self) -> u32 {
        self.max
    }

    pub fn buckets(&self) -> u32 {
        self.buckets
    }

    pub async fn count(&self) -> Result<usize> {
        self.backend.count().await
    }

    pub async fn list(&self) -> Result<Vec<ConntrackEntry>> {
        self.backend.list().await
    }

    pub async fn flush(&self) -> Result<()> {
        self.backend.flush().await
    }

    pub async fn set_max(&mut self, max: u32) -> Result<()> {
        if max < 1024 {
            bail!("conntrack max must be at least 1024, got {max}");
        }
        if max > 4_000_000 {
            bail!("conntrack max cannot exceed 4,000,000, got {max}");
        }
        self.backend.set_max(max).await?;
        self.max = max;
        Ok(())
    }

    pub async fn set_buckets(&mut self, buckets: u32) -> Result<()> {
        if buckets < 1024 {
            bail!("conntrack buckets must be at least 1024, got {buckets}");
        }
        self.backend.set_buckets(buckets).await?;
        self.buckets = buckets;
        Ok(())
    }

    pub fn usage_ratio(&self, count: usize) -> f64 {
        if self.max == 0 {
            return 0.0;
        }
        count as f64 / self.max as f64
    }

    pub async fn top_talkers(&self, limit: usize) -> Result<Vec<TalkerEntry>> {
        let entries = self.backend.list().await?;
        let mut ip_bytes: std::collections::HashMap<IpAddr, u64> = std::collections::HashMap::new();
        for e in &entries {
            *ip_bytes.entry(e.src).or_default() += e.bytes;
            *ip_bytes.entry(e.dst).or_default() += e.bytes;
        }
        let mut talkers: Vec<TalkerEntry> = ip_bytes
            .into_iter()
            .map(|(ip, bytes)| TalkerEntry { ip, bytes })
            .collect();
        use std::cmp::Reverse;
        talkers.sort_by_key(|t| Reverse(t.bytes));
        talkers.truncate(limit);
        Ok(talkers)
    }

    pub async fn protocol_distribution(&self) -> Result<Vec<ProtocolCount>> {
        let entries = self.backend.list().await?;
        let mut counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
        for e in &entries {
            *counts.entry(e.protocol).or_default() += 1;
        }
        let mut result: Vec<ProtocolCount> = counts
            .into_iter()
            .map(|(proto, count)| ProtocolCount { proto, count })
            .collect();
        use std::cmp::Reverse;
        result.sort_by_key(|p| Reverse(p.count));
        Ok(result)
    }
}

/// Network address with total bytes transferred.
#[derive(Debug, Clone, Serialize)]
pub struct TalkerEntry {
    pub ip: IpAddr,
    pub bytes: u64,
}

/// Protocol number and its connection count.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCount {
    pub proto: u8,
    pub count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBackend;

    fn setup() -> ConntrackManager<MockBackend> {
        ConntrackManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_count_empty() {
        let mgr = setup();
        assert_eq!(mgr.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_set_max() {
        let mut mgr = setup();
        mgr.set_max(1_000_000).await.unwrap();
        assert_eq!(mgr.max(), 1_000_000);
    }

    #[tokio::test]
    async fn test_set_max_too_low() {
        let mut mgr = setup();
        let err = mgr.set_max(100).await.unwrap_err();
        assert!(err.to_string().contains("at least 1024"));
    }

    #[tokio::test]
    async fn test_set_max_too_high() {
        let mut mgr = setup();
        let err = mgr.set_max(5_000_000).await.unwrap_err();
        assert!(err.to_string().contains("cannot exceed"));
    }

    #[tokio::test]
    async fn test_set_buckets() {
        let mut mgr = setup();
        mgr.set_buckets(131_072).await.unwrap();
        assert_eq!(mgr.buckets(), 131_072);
    }

    #[tokio::test]
    async fn test_flush() {
        let mut mgr = setup();
        mgr.set_max(100_000).await.unwrap();
        mgr.flush().await.unwrap();
        assert_eq!(mgr.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_usage_ratio() {
        let mgr = setup();
        assert_eq!(mgr.usage_ratio(0), 0.0);
        assert!(mgr.usage_ratio((MAX_CONNTRACK_DEFAULT / 2) as usize) > 0.0);
        assert!(mgr.usage_ratio((MAX_CONNTRACK_DEFAULT / 2) as usize) < 1.0);
    }
}
