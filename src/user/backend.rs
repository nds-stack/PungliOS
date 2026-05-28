use anyhow::{Result, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::types::*;

#[async_trait]
pub trait UserBackend: Send + Sync {
    async fn create_user(&self, user: User) -> Result<()>;
    async fn get_user(&self, username: &str) -> Result<User>;
    async fn update_user(&self, user: &User) -> Result<()>;
    async fn delete_user(&self, username: &str) -> Result<()>;
    async fn list_users(&self) -> Result<Vec<User>>;
    async fn user_count(&self) -> Result<usize>;

    async fn create_package(&self, pkg: UserPackage) -> Result<()>;
    async fn get_package(&self, name: &str) -> Result<UserPackage>;
    async fn update_package(&self, pkg: &UserPackage) -> Result<()>;
    async fn list_packages(&self) -> Result<Vec<UserPackage>>;
    async fn delete_package(&self, name: &str) -> Result<()>;

    async fn authenticate(&self, username: &str, password: &str) -> Result<User>;
    async fn set_user_enabled(&self, username: &str, enabled: bool) -> Result<()>;
    async fn set_user_package(&self, username: &str, package_name: Option<&str>) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MockUserBackend {
    users: Arc<RwLock<HashMap<String, User>>>,
    packages: Arc<RwLock<HashMap<String, UserPackage>>>,
}

impl MockUserBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserBackend for MockUserBackend {
    async fn create_user(&self, user: User) -> Result<()> {
        user.validate()
            .map_err(|e| anyhow::anyhow!("invalid user: {e}"))?;
        let mut users = self.users.write().expect("lock poisoned");
        if users.contains_key(&user.username) {
            bail!("user '{}' already exists", user.username);
        }
        users.insert(user.username.clone(), user);
        Ok(())
    }

    async fn get_user(&self, username: &str) -> Result<User> {
        self.users
            .read()
            .expect("lock poisoned")
            .get(username)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("user '{username}' not found"))
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        user.validate()
            .map_err(|e| anyhow::anyhow!("invalid user: {e}"))?;
        let mut users = self.users.write().expect("lock poisoned");
        if !users.contains_key(&user.username) {
            bail!("user '{}' not found", user.username);
        }
        users.insert(user.username.clone(), user.clone());
        Ok(())
    }

    async fn delete_user(&self, username: &str) -> Result<()> {
        let mut users = self.users.write().expect("lock poisoned");
        if users.remove(username).is_none() {
            bail!("user '{username}' not found");
        }
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<User>> {
        Ok(self
            .users
            .read()
            .expect("lock poisoned")
            .values()
            .cloned()
            .collect())
    }

    async fn user_count(&self) -> Result<usize> {
        Ok(self.users.read().expect("lock poisoned").len())
    }

    async fn create_package(&self, pkg: UserPackage) -> Result<()> {
        pkg.validate()
            .map_err(|e| anyhow::anyhow!("invalid package: {e}"))?;
        let mut packages = self.packages.write().expect("lock poisoned");
        if packages.contains_key(&pkg.name) {
            bail!("package '{}' already exists", pkg.name);
        }
        packages.insert(pkg.name.clone(), pkg);
        Ok(())
    }

    async fn get_package(&self, name: &str) -> Result<UserPackage> {
        self.packages
            .read()
            .expect("lock poisoned")
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("package '{name}' not found"))
    }

    async fn list_packages(&self) -> Result<Vec<UserPackage>> {
        Ok(self
            .packages
            .read()
            .expect("lock poisoned")
            .values()
            .cloned()
            .collect())
    }

    async fn delete_package(&self, name: &str) -> Result<()> {
        let mut packages = self.packages.write().expect("lock poisoned");
        if packages.remove(name).is_none() {
            bail!("package '{name}' not found");
        }
        Ok(())
    }

    async fn update_package(&self, pkg: &UserPackage) -> Result<()> {
        pkg.validate().map_err(|e| anyhow::anyhow!("invalid package: {e}"))?;
        let mut packages = self.packages.write().expect("lock poisoned");
        if !packages.contains_key(&pkg.name) {
            bail!("package '{}' not found", pkg.name);
        }
        packages.insert(pkg.name.clone(), pkg.clone());
        Ok(())
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<User> {
        let user = self.get_user(username).await?;
        if !user.enabled {
            bail!("user '{username}' is disabled");
        }
        if user.password != password {
            bail!("invalid password for '{username}'");
        }
        Ok(user)
    }

    async fn set_user_enabled(&self, username: &str, enabled: bool) -> Result<()> {
        let mut users = self.users.write().expect("lock poisoned");
        let user = users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("user '{username}' not found"))?;
        user.enabled = enabled;
        Ok(())
    }

    async fn set_user_package(&self, username: &str, package_name: Option<&str>) -> Result<()> {
        let mut users = self.users.write().expect("lock poisoned");
        let user = users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("user '{username}' not found"))?;
        user.package_name = package_name.map(|s| s.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> User {
        User {
            username: "testuser".into(),
            password: "testpass".into(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        }
    }

    #[tokio::test]
    async fn test_create_get_user() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let user = backend.get_user("testuser").await.unwrap();
        assert_eq!(user.username, "testuser");
    }

    #[tokio::test]
    async fn test_create_duplicate_user_rejected() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let result = backend.create_user(test_user()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_nonexistent_user() {
        let backend = MockUserBackend::new();
        let result = backend.get_user("nobody").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        backend.delete_user("testuser").await.unwrap();
        assert_eq!(backend.user_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_list_users() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let mut u2 = test_user();
        u2.username = "user2".into();
        backend.create_user(u2).await.unwrap();
        assert_eq!(backend.list_users().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_update_user() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let mut user = backend.get_user("testuser").await.unwrap();
        user.enabled = false;
        backend.update_user(&user).await.unwrap();
        let updated = backend.get_user("testuser").await.unwrap();
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_authenticate_valid() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let user = backend.authenticate("testuser", "testpass").await.unwrap();
        assert_eq!(user.username, "testuser");
    }

    #[tokio::test]
    async fn test_authenticate_wrong_password() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let result = backend.authenticate("testuser", "wrongpass").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_disabled_user() {
        let backend = MockUserBackend::new();
        let mut user = test_user();
        user.enabled = false;
        backend.create_user(user).await.unwrap();
        let result = backend.authenticate("testuser", "testpass").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_package_crud() {
        let backend = MockUserBackend::new();
        let pkg = UserPackage {
            name: "silver".into(),
            description: "Silver 10Mbps".into(),
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
        backend.create_package(pkg).await.unwrap();
        let pkg = backend.get_package("silver").await.unwrap();
        assert_eq!(pkg.name, "silver");
        assert_eq!(backend.list_packages().await.unwrap().len(), 1);
        backend.delete_package("silver").await.unwrap();
        assert_eq!(backend.list_packages().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_set_user_enabled() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        backend.set_user_enabled("testuser", false).await.unwrap();
        let user = backend.get_user("testuser").await.unwrap();
        assert!(!user.enabled);
    }

    #[tokio::test]
    async fn test_set_user_package() {
        let backend = MockUserBackend::new();
        backend.create_user(test_user()).await.unwrap();
        let pkg = UserPackage {
            name: "gold".into(),
            description: "Gold 50Mbps".into(),
            profiles: vec![BandwidthProfile {
                name: "50mbps".into(),
                upload_rate: 50000,
                download_rate: 50000,
                upload_burst: None,
                download_burst: None,
                priority: 2,
            }],
            session_timeout: None,
        };
        backend.create_package(pkg).await.unwrap();
        backend
            .set_user_package("testuser", Some("gold"))
            .await
            .unwrap();
        let user = backend.get_user("testuser").await.unwrap();
        assert_eq!(user.package_name.unwrap(), "gold");
    }
}
