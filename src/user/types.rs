use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

fn hash_password(plain: &str) -> String {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_else(|e| {
            tracing::warn!("argon2 hashing failed: {e}");
            String::new()
        })
}

fn verify_password(hash: &str, plain: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

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
    pub password_hash: String,
    pub enabled: bool,
    pub package_name: Option<String>,
    pub ip_address: Option<Ipv4Addr>,
    pub mac_address: Option<String>,
    pub notes: Option<String>,
}

impl User {
    pub fn set_password(&mut self, plain: &str) {
        if plain.len() < 4 {
            tracing::warn!("password too short ({} chars), setting anyway", plain.len());
        }
        self.password_hash = hash_password(plain);
    }

    pub fn verify_password(&self, plain: &str) -> bool {
        verify_password(&self.password_hash, plain)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("username cannot be empty".into());
        }
        if self.password_hash.is_empty() || self.password_hash.len() < 16 {
            return Err("password hash not set or invalid".into());
        }
        if self.username.len() < 3 {
            return Err("username must be at least 3 characters".into());
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
        let mut u = User {
            username: "user1".into(),
            password_hash: String::new(),
            enabled: true,
            package_name: Some("silver".into()),
            ip_address: Some(Ipv4Addr::new(10, 0, 0, 5)),
            mac_address: Some("aa:bb:cc:dd:ee:ff".into()),
            notes: None,
        };
        u.set_password("pass123");
        assert!(u.validate().is_ok());
    }

    #[test]
    fn test_user_validation_short_username() {
        let mut u = User {
            username: "ab".into(),
            password_hash: String::new(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        };
        u.set_password("pass123");
        assert!(u.validate().is_err());
    }

    #[test]
    fn test_user_validation_short_password() {
        let mut u = User {
            username: "user1".into(),
            password_hash: String::new(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        };
        // Argon2 produces valid hash even for short passwords
        u.set_password("ab");
        assert!(u.validate().is_ok());
    }
}
