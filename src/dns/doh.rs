use anyhow::Result;
use serde::Serialize;
use tokio::process::Command;

pub struct DohResolver;

#[derive(Debug, Clone, Serialize)]
pub struct DohResponse {
    pub server: String,
    pub question: String,
    pub answers: Vec<String>,
    pub response_time_ms: f64,
}

impl DohResolver {
    pub async fn resolve(domain: &str, server: &str) -> Result<DohResponse> {
        if domain.is_empty() {
            anyhow::bail!("domain cannot be empty");
        }
        let server_url = if server.is_empty() {
            "https://cloudflare-dns.com/dns-query"
        } else {
            server
        };

        let start = std::time::Instant::now();
        let url = format!("{server_url}?name={domain}&type=A");

        let output = Command::new("curl")
            .args([
                "-s",
                "-H",
                "Accept: application/dns-json",
                &url,
            ])
            .output()
            .await?;

        let elapsed = start.elapsed().as_secs_f64() * 1000.0;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("curl failed: {stderr}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let body: serde_json::Value = serde_json::from_str(&stdout)?;

        let answers: Vec<String> = body["Answer"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a["data"].as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(DohResponse {
            server: server_url.to_string(),
            question: domain.to_string(),
            answers,
            response_time_ms: elapsed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_domain() {
        assert!(DohResolver::resolve("", "").await.is_err());
    }

    #[tokio::test]
    async fn test_doh_response_struct() {
        let resp = DohResponse {
            server: "https://cloudflare-dns.com/dns-query".into(),
            question: "example.com".into(),
            answers: vec!["93.184.216.34".into()],
            response_time_ms: 42.0,
        };
        assert_eq!(resp.answers.len(), 1);
        assert!(!resp.server.is_empty());
    }
}
