use anyhow::Result;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct TracerouteHop {
    pub ttl: u32,
    pub host: Option<String>,
    pub ip: Option<IpAddr>,
    pub rtt_ms: f64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TracerouteResult {
    pub target: IpAddr,
    pub hops: Vec<TracerouteHop>,
    pub output: String,
}

pub async fn traceroute(target: IpAddr, max_ttl: u32, timeout: Duration) -> Result<TracerouteResult> {
    let output = if cfg!(target_os = "windows") {
        Command::new("tracert")
            .arg("-h")
            .arg(max_ttl.to_string())
            .arg("-w")
            .arg(timeout.as_millis().to_string())
            .arg(target.to_string())
            .output()
            .await?
    } else {
        Command::new("traceroute")
            .arg("-m")
            .arg(max_ttl.to_string())
            .arg("-w")
            .arg((timeout.as_secs_f64().ceil() as u64).to_string())
            .arg("-q")
            .arg("1")
            .arg(target.to_string())
            .output()
            .await?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    let hops = if cfg!(target_os = "windows") {
        parse_windows_tracert(&combined)
    } else {
        parse_linux_traceroute(&combined)
    };

    Ok(TracerouteResult {
        target,
        hops,
        output: combined,
    })
}

fn parse_windows_tracert(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || !line.chars().next().map_or(true, |c| c.is_ascii_digit()) {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let ttl = match parts[0].parse::<u32>() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let ip = parts
            .iter()
            .find_map(|&p| p.trim_matches('[').trim_matches(']').parse::<IpAddr>().ok());

        let rtt_ms = parts
            .iter()
            .find_map(|&p| {
                let cleaned = p.trim_end_matches("ms").trim();
                if cleaned == "<1" {
                    Some(0.5f64)
                } else if cleaned == "*" {
                    None
                } else {
                    cleaned.parse::<f64>().ok()
                }
            })
            .unwrap_or(0.0);

        let host = parts.get(1).map(|&s| s.trim_matches('[').trim_matches(']').to_string());
        let host = host.filter(|h| h.parse::<IpAddr>().is_err());

        hops.push(TracerouteHop {
            ttl,
            host,
            ip,
            rtt_ms,
            status: if rtt_ms > 0.0 {
                "ok".into()
            } else {
                "timeout".into()
            },
        });
    }
    hops
}

fn parse_linux_traceroute(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("traceroute")
            || line.starts_with("traceroute to")
        {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ttl = match parts[0].trim_end_matches(':').parse::<u32>() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let ip = parts
            .iter()
            .find_map(|&p| {
                let cleaned = p.trim_matches('(').trim_matches(')');
                cleaned.parse::<IpAddr>().ok()
            });

        let rtt_ms = parts
            .iter()
            .find_map(|&p| {
                let cleaned = p.trim_end_matches("ms").trim();
                if cleaned == "*" {
                    None
                } else {
                    cleaned.parse::<f64>().ok()
                }
            })
            .unwrap_or(0.0);

        let host = parts.get(1).map(|&s| {
            s.trim_matches('(')
                .trim_end_matches(')')
                .to_string()
        });
        let host = host.filter(|h| h.parse::<IpAddr>().is_err());

        hops.push(TracerouteHop {
            ttl,
            host,
            ip,
            rtt_ms,
            status: if rtt_ms > 0.0 {
                "ok".into()
            } else {
                "timeout".into()
            },
        });
    }
    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_windows_tracert() {
        let output = "\
  1     1 ms     2 ms     1 ms  192.168.1.1
  2    10 ms    11 ms    10 ms  10.0.0.1
  3     *        *        *     Request timed out.";

        let hops = parse_windows_tracert(output);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].ttl, 1);
        assert_eq!(hops[1].ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(hops[2].status, "timeout");
    }

    #[test]
    fn test_parse_linux_traceroute() {
        let output = "\
 1  192.168.1.1 (192.168.1.1)  1.234 ms
 2  10.0.0.1 (10.0.0.1)  10.456 ms";

        let hops = parse_linux_traceroute(output);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].ttl, 1);
        assert_eq!(hops[1].rtt_ms, 10.456);
    }
}
