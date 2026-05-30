use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;

pub struct WalledGarden {
    allowed_domains: Mutex<HashSet<String>>,
    allowed_ips: Mutex<HashSet<IpAddr>>,
}

impl WalledGarden {
    pub fn new() -> Self {
        let mut domains = HashSet::new();
        domains.insert("punglios.local".into());
        let mut ips = HashSet::new();
        ips.insert("127.0.0.1".parse().unwrap());

        Self {
            allowed_domains: Mutex::new(domains),
            allowed_ips: Mutex::new(ips),
        }
    }

    pub fn allow_domain(&self, domain: &str) {
        self.allowed_domains.lock().unwrap().insert(domain.to_string());
    }

    pub fn allow_ip(&self, ip: IpAddr) {
        self.allowed_ips.lock().unwrap().insert(ip);
    }

    pub fn is_allowed_domain(&self, domain: &str) -> bool {
        self.allowed_domains.lock().unwrap().contains(domain)
    }

    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        self.allowed_ips.lock().unwrap().contains(&ip)
    }

    pub fn remove_domain(&self, domain: &str) {
        self.allowed_domains.lock().unwrap().remove(domain);
    }

    pub fn list_domains(&self) -> Vec<String> {
        let mut list: Vec<_> = self.allowed_domains.lock().unwrap().iter().cloned().collect();
        list.sort();
        list
    }

    pub fn list_ips(&self) -> Vec<IpAddr> {
        let mut list: Vec<_> = self.allowed_ips.lock().unwrap().iter().cloned().collect();
        list.sort();
        list
    }
}

impl Default for WalledGarden {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allowed() {
        let wg = WalledGarden::new();
        assert!(wg.is_allowed_domain("punglios.local"));
    }

    #[test]
    fn test_add_and_check() {
        let wg = WalledGarden::new();
        wg.allow_domain("portal.isp.net");
        assert!(wg.is_allowed_domain("portal.isp.net"));
        assert!(!wg.is_allowed_domain("blocked.com"));
    }
}
