use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondMode {
    RoundRobin,
    ActiveBackup,
    XOR,
    Broadcast,
    Ieee8023ad,
    Tlb,
    Alb,
}

impl BondMode {
    pub fn as_kernel_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "balance-rr",
            Self::ActiveBackup => "active-backup",
            Self::XOR => "balance-xor",
            Self::Broadcast => "broadcast",
            Self::Ieee8023ad => "802.3ad",
            Self::Tlb => "balance-tlb",
            Self::Alb => "balance-alb",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "round-robin" | "balance-rr" => Some(Self::RoundRobin),
            "active-backup" => Some(Self::ActiveBackup),
            "xor" | "balance-xor" => Some(Self::XOR),
            "broadcast" => Some(Self::Broadcast),
            "802.3ad" | "lacp" => Some(Self::Ieee8023ad),
            "tlb" | "balance-tlb" => Some(Self::Tlb),
            "alb" | "balance-alb" => Some(Self::Alb),
            _ => None,
        }
    }
}

impl std::fmt::Display for BondMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_kernel_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LacpRate {
    Slow,
    Fast,
}

impl LacpRate {
    pub fn as_kernel_val(&self) -> u8 {
        match self {
            Self::Slow => 0,
            Self::Fast => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BondInterface {
    pub name: String,
    pub mode: BondMode,
    pub slaves: Vec<String>,
    pub mtu: u16,
    pub lacp_rate: Option<LacpRate>,
    pub min_links: Option<u32>,
    pub miimon: Option<u32>,
    pub updelay: Option<u32>,
    pub downdelay: Option<u32>,
    pub enabled: bool,
    pub addresses: Vec<String>,
}

impl BondInterface {
    pub fn new(name: &str, mode: BondMode) -> Self {
        Self {
            name: name.to_string(),
            mode,
            slaves: vec![],
            mtu: 1500,
            lacp_rate: None,
            min_links: None,
            miimon: Some(100),
            updelay: None,
            downdelay: None,
            enabled: true,
            addresses: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BondStatus {
    pub bonds_count: usize,
    pub total_slaves: usize,
    pub enabled_count: usize,
    pub bonds: Vec<BondInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BondInfo {
    pub name: String,
    pub mode: BondMode,
    pub slave_count: usize,
    pub enabled: bool,
    pub active_slave: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bond_mode_kernel_str() {
        assert_eq!(BondMode::Ieee8023ad.as_kernel_str(), "802.3ad");
        assert_eq!(BondMode::ActiveBackup.as_kernel_str(), "active-backup");
    }

    #[test]
    fn test_bond_mode_from_str() {
        assert_eq!(BondMode::from_str("lacp"), Some(BondMode::Ieee8023ad));
        assert_eq!(BondMode::from_str("balance-rr"), Some(BondMode::RoundRobin));
        assert_eq!(BondMode::from_str("unknown"), None);
    }

    #[test]
    fn test_bond_interface_creation() {
        let bond = BondInterface::new("bond0", BondMode::Ieee8023ad);
        assert_eq!(bond.name, "bond0");
        assert_eq!(bond.mode, BondMode::Ieee8023ad);
        assert!(bond.slaves.is_empty());
    }
}
