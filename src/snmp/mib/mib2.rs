use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct MibEntry {
    pub oid: String,
    pub name: String,
    pub r#type: &'static str,
    pub value: String,
}

pub struct Mib2;

impl Mib2 {
    pub fn system() -> Vec<MibEntry> {
        vec![
            MibEntry {
                oid: ".1.3.6.1.2.1.1.1.0".into(),
                name: "sysDescr".into(),
                r#type: "OctetString",
                value: "PungliOS Rust-native ISP/WISP platform".into(),
            },
            MibEntry {
                oid: ".1.3.6.1.2.1.1.2.0".into(),
                name: "sysObjectID".into(),
                r#type: "ObjectIdentifier",
                value: ".1.3.6.1.4.1.64512.1.1".into(),
            },
            MibEntry {
                oid: ".1.3.6.1.2.1.1.3.0".into(),
                name: "sysUpTime".into(),
                r#type: "TimeTicks",
                value: "0".into(),
            },
            MibEntry {
                oid: ".1.3.6.1.2.1.1.4.0".into(),
                name: "sysContact".into(),
                r#type: "OctetString",
                value: "admin@punglios.local".into(),
            },
            MibEntry {
                oid: ".1.3.6.1.2.1.1.5.0".into(),
                name: "sysName".into(),
                r#type: "OctetString",
                value: "PungliOS".into(),
            },
            MibEntry {
                oid: ".1.3.6.1.2.1.1.6.0".into(),
                name: "sysLocation".into(),
                r#type: "OctetString",
                value: "Unknown".into(),
            },
        ]
    }

    pub fn interfaces() -> Vec<MibEntry> {
        vec![
            MibEntry {
                oid: ".1.3.6.1.2.1.2.1.0".into(),
                name: "ifNumber".into(),
                r#type: "Integer32",
                value: "0".into(),
            },
        ]
    }

    pub fn all() -> Vec<MibEntry> {
        let mut entries = Self::system();
        entries.extend(Self::interfaces());
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_mib() {
        let entries = Mib2::system();
        assert!(entries.len() >= 6);
        assert_eq!(entries[0].name, "sysDescr");
    }
}
