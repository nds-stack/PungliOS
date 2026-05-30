use anyhow::Result;
use serde::Serialize;
use std::time::Instant;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Serialize)]
pub struct TrafficGenResult {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub duration_secs: f64,
    pub throughput_mbps: f64,
}

pub async fn generate_udp(target: &str, port: u16, packet_size: usize, packets: u64) -> Result<TrafficGenResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let remote = format!("{target}:{port}");
    let data = vec![0u8; packet_size.min(1472)];
    let start = Instant::now();
    let mut sent = 0u64;
    for _ in 0..packets {
        sock.send_to(&data, &remote).await?;
        sent += data.len() as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let mbps = if elapsed > 0.0 { (sent as f64 * 8.0) / (elapsed * 1_000_000.0) } else { 0.0 };
    Ok(TrafficGenResult { target: target.to_string(), port, protocol: "udp".into(), bytes_sent: sent, packets_sent: packets, duration_secs: elapsed, throughput_mbps: mbps })
}

#[cfg(test)]
mod tests { use super::*; #[tokio::test] async fn test_result() { let r = TrafficGenResult { target: "10.0.0.1".into(), port: 5000, protocol: "udp".into(), bytes_sent: 1000, packets_sent: 10, duration_secs: 1.0, throughput_mbps: 8.0 }; assert_eq!(r.packets_sent, 10); } }
