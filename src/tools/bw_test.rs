use anyhow::Result;
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize)]
pub struct BwTestResult {
    pub target: String,
    pub duration_secs: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub throughput_mbps: f64,
    pub role: String,
}

pub struct BandwidthTest {
    results: Mutex<Vec<BwTestResult>>,
}

impl BandwidthTest {
    pub fn new() -> Self {
        Self {
            results: Mutex::new(Vec::new()),
        }
    }

    pub async fn start_server(port: u16, duration_secs: u64) -> Result<BwTestResult> {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
        let start = Instant::now();

        let (mut stream, addr) = listener.accept().await?;
        let mut buf = vec![0u8; 65536];
        let mut total_bytes = 0u64;

        loop {
            let elapsed = start.elapsed();
            if elapsed >= Duration::from_secs(duration_secs) {
                break;
            }
            let remaining = Duration::from_secs(duration_secs).saturating_sub(elapsed);
            match timeout(remaining, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => total_bytes += n as u64,
                _ => break,
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let mbps = if elapsed > 0.0 {
            (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        Ok(BwTestResult {
            target: addr.to_string(),
            duration_secs: elapsed,
            bytes_sent: 0,
            bytes_received: total_bytes,
            throughput_mbps: mbps,
            role: "server".into(),
        })
    }

    pub async fn start_client(target: &str, port: u16, duration_secs: u64) -> Result<BwTestResult> {
        let addr = format!("{target}:{port}");
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => anyhow::bail!("connection failed: {e}"),
            Err(_) => anyhow::bail!("connection timeout"),
        };

        let data = vec![0u8; 65536];
        let start = Instant::now();
        let mut total_bytes = 0u64;

        loop {
            let elapsed = start.elapsed();
            if elapsed >= Duration::from_secs(duration_secs) {
                break;
            }
            let remaining = Duration::from_secs(duration_secs).saturating_sub(elapsed);
            match timeout(remaining, stream.write_all(&data)).await {
                Ok(Ok(_)) => total_bytes += data.len() as u64,
                _ => break,
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        let mbps = if elapsed > 0.0 {
            (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        Ok(BwTestResult {
            target: target.to_string(),
            duration_secs: elapsed,
            bytes_sent: total_bytes,
            bytes_received: 0,
            throughput_mbps: mbps,
            role: "client".into(),
        })
    }
}

impl Default for BandwidthTest {
    fn default() -> Self {
        Self::new()
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_creation() {
        let result = BwTestResult {
            target: "10.0.0.1".into(),
            duration_secs: 5.0,
            bytes_sent: 1000000,
            bytes_received: 0,
            throughput_mbps: 1.6,
            role: "client".into(),
        };
        assert_eq!(result.target, "10.0.0.1");
    }
}
