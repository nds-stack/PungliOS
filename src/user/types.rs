use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandwidthProfile {
    pub name: String,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub upload_burst: Option<u64>,
    pub download_burst: Option<u64>,
    pub priority: u8,
}

impl BandwidthProfile {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("profile name cannot be empty".into());
        }
        if self.upload_rate == 0 && self.download_rate == 0 {
            return Err("at least one of upload_rate or download_rate must be > 0".into());
        }
        if self.priority > 7 {
            return Err("priority must be 0-7".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserPackage {
    pub name: String,
    pub description: String,
    pub profiles: Vec<BandwidthProfile>,
    pub session_timeout: Option<u32>,
}

impl UserPackage {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("package name cannot be empty".into());
        }
        if self.profiles.is_empty() {
            return Err("at least one bandwidth profile required".into());
        }
        for p in &self.profiles {
            p.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub username: String,
    pub password: String,
    pub enabled: bool,
    pub package_name: Option<String>,
    pub ip_address: Option<Ipv4Addr>,
    pub mac_address: Option<String>,
    pub notes: Option<String>,
}

impl User {
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("username cannot be empty".into());
        }
        if self.password.is_empty() {
            return Err("password cannot be empty".into());
        }
        if self.username.len() < 3 {
            return Err("username must be at least 3 characters".into());
        }
        if self.password.len() < 4 {
            return Err("password must be at least 4 characters".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UserStatus {
    Active,
    Suspended,
    Expired,
    Disabled,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserSession {
    pub username: String,
    pub session_id: String,
    pub session_type: SessionType,
    pub ip_address: Option<Ipv4Addr>,
    pub mac_address: Option<String>,
    pub connected_at: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SessionType {
    Pppoe,
    Dhcp,
    Static,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_validation_valid() {
        let p = BandwidthProfile {
            name: "10mbps".into(),
            upload_rate: 10000,
            download_rate: 10000,
            upload_burst: None,
            download_burst: None,
            priority: 3,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_profile_validation_empty_name() {
        let p = BandwidthProfile {
            name: "".into(),
            upload_rate: 10000,
            download_rate: 10000,
            upload_burst: None,
            download_burst: None,
            priority: 3,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_profile_validation_zero_rates() {
        let p = BandwidthProfile {
            name: "zero".into(),
            upload_rate: 0,
            download_rate: 0,
            upload_burst: None,
            download_burst: None,
            priority: 3,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_profile_validation_priority_range() {
        let valid = BandwidthProfile {
            name: "ok".into(),
            upload_rate: 1000,
            download_rate: 1000,
            upload_burst: None,
            download_burst: None,
            priority: 7,
        };
        assert!(valid.validate().is_ok());

        let invalid = BandwidthProfile {
            name: "bad".into(),
            upload_rate: 1000,
            download_rate: 1000,
            upload_burst: None,
            download_burst: None,
            priority: 8,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_package_validation() {
        let pkg = UserPackage {
            name: "silver".into(),
            description: "Silver package 10Mbps".into(),
            profiles: vec![BandwidthProfile {
                name: "10mbps".into(),
                upload_rate: 10000,
                download_rate: 10000,
                upload_burst: None,
                download_burst: None,
                priority: 3,
            }],
            session_timeout: None,
        };
        assert!(pkg.validate().is_ok());
    }

    #[test]
    fn test_package_validation_empty_profiles() {
        let pkg = UserPackage {
            name: "empty".into(),
            description: "".into(),
            profiles: vec![],
            session_timeout: None,
        };
        assert!(pkg.validate().is_err());
    }

    #[test]
    fn test_user_validation_valid() {
        let u = User {
            username: "user1".into(),
            password: "pass123".into(),
            enabled: true,
            package_name: Some("silver".into()),
            ip_address: Some(Ipv4Addr::new(10, 0, 0, 5)),
            mac_address: Some("aa:bb:cc:dd:ee:ff".into()),
            notes: None,
        };
        assert!(u.validate().is_ok());
    }

    #[test]
    fn test_user_validation_short_username() {
        let u = User {
            username: "ab".into(),
            password: "pass123".into(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        };
        assert!(u.validate().is_err());
    }

    #[test]
    fn test_user_validation_short_password() {
        let u = User {
            username: "user1".into(),
            password: "ab".into(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        };
        assert!(u.validate().is_err());
    }
}
