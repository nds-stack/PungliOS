use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VrrpInstance {
    pub vrid: u8,
    pub name: String,
    pub interface: String,
    pub priority: u8,
    pub virtual_ip: String,
    pub virtual_prefix: u8,
    pub advert_interval: u8,
    pub preempt: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum VrrpState {
    Init,
    Backup,
    Master,
}

#[derive(Debug, Clone, Serialize)]
pub struct VrrpStatus {
    pub master_instance: Option<String>,
    pub instances_count: usize,
    pub master_count: usize,
    pub backup_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrrp_instance_creation() {
        let inst = VrrpInstance {
            vrid: 1,
            name: "vlan10-vip".into(),
            interface: "eth0".into(),
            priority: 100,
            virtual_ip: "10.0.0.254".into(),
            virtual_prefix: 24,
            advert_interval: 1,
            preempt: true,
            enabled: true,
        };
        assert_eq!(inst.vrid, 1);
        assert_eq!(inst.virtual_ip, "10.0.0.254");
    }
}
