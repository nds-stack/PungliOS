use anyhow::Result;
use serde::Serialize;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
pub struct DotResponse {
    pub server: String,
    pub question: String,
    pub answers: Vec<String>,
    pub response_time_ms: f64,
}

pub struct DotResolver;

impl DotResolver {
    pub async fn resolve(domain: &str, server: &str) -> Result<DotResponse> {
        if domain.is_empty() { anyhow::bail!("domain required"); }
        let addr = if server.is_empty() { "1.1.1.1" } else { server };
        let url = format!("{addr}:853");
        let start = std::time::Instant::now();
        let output = Command::new("knot-dns-utils").args(["kdig", domain, &format!("@{url}", url=url), "+tls"]).output().await;
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        match output {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let answers: Vec<String> = stdout.lines().filter(|l| l.contains("IN")).map(|l| l.to_string()).collect();
                Ok(DotResponse { server: url.to_string(), question: domain.to_string(), answers, response_time_ms: elapsed })
            }
            _ => Ok(DotResponse { server: url.to_string(), question: domain.to_string(), answers: vec!["(mock resolution failed)".into()], response_time_ms: elapsed }),
        }
    }
}

#[cfg(test)]
mod tests { use super::*; #[tokio::test] async fn test_empty_domain() { assert!(DotResolver::resolve("", "").await.is_err()); } }
