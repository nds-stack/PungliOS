use anyhow::{Result, bail};
use std::net::IpAddr;

pub struct HotspotAuth;

impl HotspotAuth {
    pub fn validate(username: &str, password: &str) -> Result<()> {
        if username.is_empty() {
            bail!("username cannot be empty");
        }
        if password.is_empty() {
            bail!("password cannot be empty");
        }
        if username.len() > 64 {
            bail!("username too long (max 64 chars)");
        }
        Ok(())
    }

    pub fn authenticate(username: &str, password: &str, _ip: IpAddr, _mac: &str) -> Result<bool> {
        Self::validate(username, password)?;
        // In production: RADIUS auth via RadiusClient
        // For mock: accept all valid credentials
        Ok(!username.is_empty() && !password.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty() {
        assert!(HotspotAuth::validate("", "pass").is_err());
        assert!(HotspotAuth::validate("user", "").is_err());
    }

    #[test]
    fn test_validate_valid() {
        assert!(HotspotAuth::validate("user1", "pass123").is_ok());
    }

    #[test]
    fn test_authenticate() {
        let ip: IpAddr = "10.0.0.100".parse().unwrap();
        let result = HotspotAuth::authenticate("user1", "pass123", ip, "aa:bb:cc:dd:ee:01").unwrap();
        assert!(result);
    }
}
