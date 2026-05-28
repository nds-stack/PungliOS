pub mod backend;
pub mod types;

use anyhow::Result;
use std::net::Ipv4Addr;

pub use backend::*;
pub use types::*;

pub struct UserManager<T: UserBackend> {
    backend: T,
}

impl<T: UserBackend> UserManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn create_user(&self, user: User) -> Result<()> {
        self.backend.create_user(user).await
    }

    pub async fn get_user(&self, username: &str) -> Result<User> {
        self.backend.get_user(username).await
    }

    pub async fn update_user(&self, user: &User) -> Result<()> {
        self.backend.update_user(user).await
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        self.backend.delete_user(username).await
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        self.backend.list_users().await
    }

    pub async fn user_count(&self) -> Result<usize> {
        self.backend.user_count().await
    }

    pub async fn create_package(&self, pkg: UserPackage) -> Result<()> {
        self.backend.create_package(pkg).await
    }

    pub async fn get_package(&self, name: &str) -> Result<UserPackage> {
        self.backend.get_package(name).await
    }

    pub async fn update_package(&self, pkg: &UserPackage) -> Result<()> {
        self.backend.update_package(pkg).await
    }

    pub async fn list_packages(&self) -> Result<Vec<UserPackage>> {
        self.backend.list_packages().await
    }

    pub async fn delete_package(&self, name: &str) -> Result<()> {
        self.backend.delete_package(name).await
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<User> {
        self.backend.authenticate(username, password).await
    }

    pub async fn enable_user(&self, username: &str) -> Result<()> {
        self.backend.set_user_enabled(username, true).await
    }

    pub async fn disable_user(&self, username: &str) -> Result<()> {
        self.backend.set_user_enabled(username, false).await
    }

    pub async fn assign_package(&self, username: &str, package_name: &str) -> Result<()> {
        let _ = self.backend.get_package(package_name).await?;
        self.backend
            .set_user_package(username, Some(package_name))
            .await
    }

    pub async fn remove_package(&self, username: &str) -> Result<()> {
        self.backend.set_user_package(username, None).await
    }

    pub async fn get_user_bandwidth(&self, username: &str) -> Result<Vec<BandwidthProfile>> {
        let user = self.backend.get_user(username).await?;
        match user.package_name {
            Some(ref pkg_name) => {
                let pkg = self.backend.get_package(pkg_name).await?;
                Ok(pkg.profiles)
            }
            None => Ok(vec![]),
        }
    }

    pub async fn assign_ip(&self, username: &str, ip: Ipv4Addr) -> Result<()> {
        let mut user = self.backend.get_user(username).await?;
        user.ip_address = Some(ip);
        self.backend.update_user(&user).await
    }

    pub async fn assign_mac(&self, username: &str, mac: &str) -> Result<()> {
        let mut user = self.backend.get_user(username).await?;
        user.mac_address = Some(mac.to_string());
        self.backend.update_user(&user).await
    }

    pub async fn find_by_ip(&self, ip: Ipv4Addr) -> Result<Option<User>> {
        let users = self.backend.list_users().await?;
        Ok(users.into_iter().find(|u| u.ip_address == Some(ip)))
    }

    pub async fn find_by_mac(&self, mac: &str) -> Result<Option<User>> {
        let users = self.backend.list_users().await?;
        Ok(users
            .into_iter()
            .find(|u| u.mac_address.as_deref() == Some(mac)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> UserManager<MockUserBackend> {
        UserManager::new(MockUserBackend::new())
    }

    fn test_user() -> User {
        User {
            username: "user1".into(),
            password: "pass1".into(),
            enabled: true,
            package_name: None,
            ip_address: None,
            mac_address: None,
            notes: None,
        }
    }

    fn test_package(name: &str) -> UserPackage {
        UserPackage {
            name: name.into(),
            description: format!("{name} package"),
            profiles: vec![BandwidthProfile {
                name: format!("{name}-profile"),
                upload_rate: 10000,
                download_rate: 10000,
                upload_burst: None,
                download_burst: None,
                priority: 3,
            }],
            session_timeout: None,
        }
    }

    #[tokio::test]
    async fn test_manager_user_lifecycle() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        assert_eq!(mgr.user_count().await.unwrap(), 1);

        let user = mgr.get_user("user1").await.unwrap();
        assert_eq!(user.username, "user1");

        mgr.delete_user("user1").await.unwrap();
        assert_eq!(mgr.user_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_manager_enable_disable() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();

        mgr.disable_user("user1").await.unwrap();
        let user = mgr.get_user("user1").await.unwrap();
        assert!(!user.enabled);

        mgr.enable_user("user1").await.unwrap();
        let user = mgr.get_user("user1").await.unwrap();
        assert!(user.enabled);
    }

    #[tokio::test]
    async fn test_manager_assign_package() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        mgr.create_package(test_package("silver")).await.unwrap();

        mgr.assign_package("user1", "silver").await.unwrap();
        let user = mgr.get_user("user1").await.unwrap();
        assert_eq!(user.package_name.unwrap(), "silver");

        let profiles = mgr.get_user_bandwidth("user1").await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "silver-profile");
    }

    #[tokio::test]
    async fn test_manager_remove_package() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        mgr.create_package(test_package("silver")).await.unwrap();
        mgr.assign_package("user1", "silver").await.unwrap();
        mgr.remove_package("user1").await.unwrap();

        let user = mgr.get_user("user1").await.unwrap();
        assert!(user.package_name.is_none());
    }

    #[tokio::test]
    async fn test_manager_assign_ip() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        mgr.assign_ip("user1", ip).await.unwrap();

        let user = mgr.get_user("user1").await.unwrap();
        assert_eq!(user.ip_address.unwrap(), ip);
    }

    #[tokio::test]
    async fn test_manager_assign_mac() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        mgr.assign_mac("user1", "aa:bb:cc:dd:ee:ff").await.unwrap();

        let user = mgr.get_user("user1").await.unwrap();
        assert_eq!(user.mac_address.unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[tokio::test]
    async fn test_manager_find_by_ip() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        mgr.assign_ip("user1", ip).await.unwrap();

        let found = mgr.find_by_ip(ip).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().username, "user1");

        let not_found = mgr.find_by_ip(Ipv4Addr::new(10, 0, 0, 99)).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_manager_find_by_mac() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();
        mgr.assign_mac("user1", "aa:bb:cc:dd:ee:ff").await.unwrap();

        let found = mgr.find_by_mac("aa:bb:cc:dd:ee:ff").await.unwrap();
        assert!(found.is_some());

        let not_found = mgr.find_by_mac("00:00:00:00:00:00").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_manager_authenticate() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();

        let user = mgr.authenticate("user1", "pass1").await.unwrap();
        assert_eq!(user.username, "user1");
    }

    #[tokio::test]
    async fn test_manager_get_user_bandwidth_no_package() {
        let mgr = setup();
        mgr.create_user(test_user()).await.unwrap();

        let profiles = mgr.get_user_bandwidth("user1").await.unwrap();
        assert!(profiles.is_empty());
    }
}
