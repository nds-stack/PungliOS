use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PrivateMibEntry {
    pub oid: String,
    pub name: String,
    pub description: String,
    pub r#type: &'static str,
}

pub struct PungliOSMib;

impl PungliOSMib {
    pub fn entries() -> Vec<PrivateMibEntry> {
        vec![
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.1".into(),
                name: "pungliosVersion".into(),
                description: "PungliOS software version".into(),
                r#type: "OctetString",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.2".into(),
                name: "pungliosUptime".into(),
                description: "System uptime in seconds".into(),
                r#type: "Integer32",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.3".into(),
                name: "pungliosActiveSessions".into(),
                description: "Number of active PPPoE sessions".into(),
                r#type: "Integer32",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.4".into(),
                name: "pungliosBandwidthUsage".into(),
                description: "Current bandwidth usage in bps".into(),
                r#type: "Gauge32",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.5".into(),
                name: "pungliosCpuUsage".into(),
                description: "CPU usage percentage".into(),
                r#type: "Integer32",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.6".into(),
                name: "pungliosMemoryUsage".into(),
                description: "Memory usage percentage".into(),
                r#type: "Integer32",
            },
            PrivateMibEntry {
                oid: ".1.3.6.1.4.1.64512.7".into(),
                name: "pungliosConntrackCount".into(),
                description: "Current conntrack entry count".into(),
                r#type: "Gauge32",
            },
        ]
    }
}
