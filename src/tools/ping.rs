use anyhow::Result;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct PingResult {
    pub target: IpAddr,
    pub count: u32,
    pub transmitted: u32,
    pub received: u32,
    pub packet_loss_pct: f64,
    pub min_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub output: String,
}

pub struct Pinger;

impl Pinger {
    pub async fn ping(
        target: IpAddr,
        count: u32,
        _interval: Duration,
        timeout: Duration,
    ) -> Result<PingResult> {
        let output = Command::new("ping")
            .arg("-n")
            .arg(count.to_string())
            .arg("-w")
            .arg(timeout.as_millis().to_string())
            .arg(target.to_string())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = format!("{stdout}{stderr}");

        let transmitted = parse_windows_ping_stat(&combined, "Sent = ")
            .or_else(|| parse_windows_ping_stat(&combined, "ransmitted"))
            .or_else(|| parse_linux_ping_transmitted(&combined))
            .unwrap_or(count);

        let received = parse_windows_ping_stat(&combined, "Received = ")
            .or_else(|| parse_windows_ping_stat(&combined, "eceived"))
            .or_else(|| parse_linux_ping_received(&combined))
            .unwrap_or(0);

        let packet_loss_pct = if transmitted > 0 {
            ((transmitted - received) as f64 / transmitted as f64) * 100.0
        } else {
            100.0
        };

        let (min_rtt_ms, avg_rtt_ms, max_rtt_ms) =
            parse_windows_rtt(&combined).unwrap_or((0.0, 0.0, 0.0));

        Ok(PingResult {
            target,
            count,
            transmitted,
            received,
            packet_loss_pct,
            min_rtt_ms,
            avg_rtt_ms,
            max_rtt_ms,
            output: combined,
        })
    }
}

fn parse_windows_ping_stat(output: &str, label: &str) -> Option<u32> {
    for line in output.lines() {
        if line.contains(label) {
            for part in line.split(',') {
                let trimmed = part.trim();
                if let Some(val_str) = trimmed
                    .split('=')
                    .nth(1)
                    .map(|s| s.trim().trim_matches(|c: char| !c.is_ascii_digit()))
                {
                    if let Ok(val) = val_str.parse::<u32>() {
                        return Some(val);
                    }
                }
            }
        }
    }
    None
}

fn parse_linux_ping_transmitted(output: &str) -> Option<u32> {
    for line in output.lines() {
        if line.contains("packets transmitted") {
            if let Some(count) = line.split_whitespace().next() {
                return count.parse::<u32>().ok();
            }
        }
    }
    None
}

fn parse_linux_ping_received(output: &str) -> Option<u32> {
    for line in output.lines() {
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                return parts[3].parse::<u32>().ok();
            }
        }
    }
    None
}

fn parse_windows_rtt(output: &str) -> Option<(f64, f64, f64)> {
    for line in output.lines() {
        if line.contains("Minimum = ") || line.contains("Min = ") {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let min = extract_number(parts[0]);
                let max = extract_number(parts[1]);
                let avg = extract_number(parts[2]);
                if let (Some(min), Some(max), Some(avg)) = (min, max, avg) {
                    return Some((min, avg, max));
                }
            }
        }
    }
    None
}

fn extract_number(s: &str) -> Option<f64> {
    s.split('=')
        .nth(1)
        .and_then(|v| {
            v.trim()
                .trim_start_matches(' ')
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .next()
                .and_then(|n| n.parse::<f64>().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ping_result_creation() {
        let result = PingResult {
            target: "8.8.8.8".parse().unwrap(),
            count: 4,
            transmitted: 4,
            received: 4,
            packet_loss_pct: 0.0,
            min_rtt_ms: 10.0,
            avg_rtt_ms: 12.0,
            max_rtt_ms: 15.0,
            output: "test output".into(),
        };
        assert_eq!(result.transmitted, 4);
        assert_eq!(result.received, 4);
        assert_eq!(result.packet_loss_pct, 0.0);
    }

    #[test]
    fn test_parse_windows_ping_stat() {
        let output = "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),";
        assert_eq!(parse_windows_ping_stat(output, "Sent = "), Some(4));
        assert_eq!(parse_windows_ping_stat(output, "Received = "), Some(4));
    }

    #[test]
    fn test_parse_linux_ping() {
        let output = "4 packets transmitted, 4 received, 0% packet loss, time 3004ms";
        assert_eq!(parse_linux_ping_transmitted(output), Some(4));
        assert_eq!(parse_linux_ping_received(output), Some(4));
    }
}
