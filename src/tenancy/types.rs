use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub enabled: bool,
    pub max_users: Option<u32>,
    pub max_bandwidth: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantManagerStatus {
    pub total_tenants: usize,
    pub enabled_tenants: usize,
    pub total_users_across_tenants: usize,
}
