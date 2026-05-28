use anyhow::{Result, bail};
use std::collections::HashMap;

pub const ETH_PPPOE_DISCOVERY: u16 = 0x8863;
pub const ETH_PPPOE_SESSION: u16 = 0x8864;

pub const PPPOE_VERSION: u8 = 0x01;
pub const PPPOE_TYPE: u8 = 0x01;

pub const PADI: u8 = 0x09;
pub const PADO: u8 = 0x07;
pub const PADR: u8 = 0x19;
pub const PADS: u8 = 0x65;
pub const PADT: u8 = 0xa7;

pub const TAG_END_OF_LIST: u16 = 0x0000;
pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;
pub const TAG_VENDOR_SPECIFIC: u16 = 0x0105;
pub const TAG_RELAY_SESSION_ID: u16 = 0x0110;
pub const TAG_SERVICE_NAME_ERROR: u16 = 0x0201;
pub const TAG_AC_SYSTEM_ERROR: u16 = 0x0202;
pub const TAG_GENERIC_ERROR: u16 = 0x0203;

#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    pub tag_type: u16,
    pub value: Vec<u8>,
}

impl Tag {
    pub fn new(tag_type: u16, value: Vec<u8>) -> Self {
        Self { tag_type, value }
    }

    #[allow(dead_code)]
    pub fn from_str(tag_type: u16, s: &str) -> Self {
        Self {
            tag_type,
            value: s.as_bytes().to_vec(),
        }
    }

    pub fn from_string(tag_type: u16, s: String) -> Self {
        Self {
            tag_type,
            value: s.into_bytes(),
        }
    }

    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
    }

    pub fn encoded_len(&self) -> usize {
        4 + self.value.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(&self.tag_type.to_be_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            bail!("tag too short: {} bytes", data.len());
        }
        let tag_type = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            bail!("tag data too short: need {}, got {}", 4 + len, data.len());
        }
        let value = data[4..4 + len].to_vec();
        Ok((Self { tag_type, value }, 4 + len))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PppoePacket {
    pub code: u8,
    pub session_id: u16,
    pub tags: Vec<Tag>,
}

impl PppoePacket {
    pub fn new(code: u8, session_id: u16) -> Self {
        Self {
            code,
            session_id,
            tags: vec![],
        }
    }

    pub fn name(&self) -> &'static str {
        match self.code {
            PADI => "PADI",
            PADO => "PADO",
            PADR => "PADR",
            PADS => "PADS",
            PADT => "PADT",
            _ => "UNKNOWN",
        }
    }

    pub fn code_name(code: u8) -> &'static str {
        match code {
            PADI => "PADI",
            PADO => "PADO",
            PADR => "PADR",
            PADS => "PADS",
            PADT => "PADT",
            _ => "UNKNOWN",
        }
    }

    pub fn add_tag(&mut self, tag: Tag) {
        self.tags.push(tag);
    }

    pub fn find_tag(&self, tag_type: u16) -> Option<&Tag> {
        self.tags.iter().find(|t| t.tag_type == tag_type)
    }

    pub fn find_tag_str(&self, tag_type: u16) -> Option<String> {
        self.find_tag(tag_type).and_then(|t| t.as_string())
    }

    pub fn tag_map(&self) -> HashMap<u16, Vec<&Tag>> {
        let mut map: HashMap<u16, Vec<&Tag>> = HashMap::new();
        for tag in &self.tags {
            map.entry(tag.tag_type).or_default().push(tag);
        }
        map
    }

    pub fn encoded_len(&self) -> usize {
        6 + self.tags.iter().map(|t| t.encoded_len()).sum::<usize>()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.push(PPPOE_VERSION << 4 | PPPOE_TYPE);
        buf.push(self.code);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        let payload_start = buf.len();
        buf.extend_from_slice(&[0, 0]);
        for tag in &self.tags {
            buf.extend_from_slice(&tag.encode());
        }
        let payload_len = (buf.len() - payload_start - 2) as u16;
        buf[payload_start] = (payload_len >> 8) as u8;
        buf[payload_start + 1] = (payload_len & 0xff) as u8;
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            bail!("PPPoE packet too short: {} bytes", data.len());
        }
        let version_type = data[0];
        let version = version_type >> 4;
        let tp = version_type & 0x0f;
        if version != 0x01 || tp != 0x01 {
            bail!(
                "invalid PPPoE version/type: version={}, type={}",
                version,
                tp
            );
        }
        let code = data[1];
        let session_id = u16::from_be_bytes([data[2], data[3]]);
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let tag_data = &data[6..];
        let tag_end = std::cmp::min(tag_data.len(), payload_len);
        let mut tags = Vec::new();
        let mut offset = 0;
        while offset + 4 <= tag_end {
            let tag_type = u16::from_be_bytes([tag_data[offset], tag_data[offset + 1]]);
            if tag_type == TAG_END_OF_LIST {
                break;
            }
            let tag_len = u16::from_be_bytes([tag_data[offset + 2], tag_data[offset + 3]]) as usize;
            if offset + 4 + tag_len > tag_end {
                bail!(
                    "tag data overflow: tag_len={}, remaining={}",
                    tag_len,
                    tag_end - offset
                );
            }
            let value = tag_data[offset + 4..offset + 4 + tag_len].to_vec();
            tags.push(Tag { tag_type, value });
            offset += 4 + tag_len;
        }
        Ok(Self {
            code,
            session_id,
            tags,
        })
    }

    pub fn is_discovery(&self) -> bool {
        matches!(self.code, PADI | PADO | PADR | PADS | PADT)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DiscoveryState {
    Idle,
    PadiSent {
        host_uniq: Vec<u8>,
    },
    PadoReceived {
        ac_name: String,
        cookie: Vec<u8>,
        host_uniq: Vec<u8>,
    },
    PadrSent {
        ac_name: String,
        host_uniq: Vec<u8>,
    },
    Established {
        session_id: u16,
        ac_name: String,
    },
    Terminated,
}

impl DiscoveryState {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Established { .. })
    }

    pub fn session_id(&self) -> Option<u16> {
        match self {
            Self::Established { session_id, .. } => Some(*session_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PppoeClientConfig {
    pub interface: String,
    pub service_name: Option<String>,
    pub username: String,
    pub password: String,
    pub auth_protocol: AuthProtocol,
    pub host_uniq: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthProtocol {
    Pap,
    Chap,
    MsChapV2,
}

#[derive(Debug, Clone)]
pub struct PppoeServerConfig {
    pub interfaces: Vec<String>,
    pub ac_name: String,
    pub service_name: Option<String>,
    pub max_sessions: usize,
}

#[derive(Debug, Clone)]
pub struct PppoeSession {
    pub session_id: u16,
    pub iface: String,
    pub client_mac: Option<[u8; 6]>,
    pub username: Option<String>,
    pub ac_cookie: Vec<u8>,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LcpConfig {
    pub mru: u16,
    pub auth_protocol: Option<AuthProtocol>,
    pub magic_number: Option<u32>,
}

impl Default for LcpConfig {
    fn default() -> Self {
        Self {
            mru: 1492,
            auth_protocol: None,
            magic_number: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpcpConfig {
    pub ip_address: Option<std::net::Ipv4Addr>,
    pub dns_servers: Vec<std::net::Ipv4Addr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_encode_decode_roundtrip() {
        let tag = Tag::from_str(TAG_SERVICE_NAME, "my-isp");
        let encoded = tag.encode();
        let (decoded, consumed) = Tag::decode(&encoded).unwrap();
        assert_eq!(decoded.tag_type, TAG_SERVICE_NAME);
        assert_eq!(decoded.as_string().unwrap(), "my-isp");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_packet_encode_decode_padi() {
        let mut pkt = PppoePacket::new(PADI, 0);
        pkt.add_tag(Tag::from_str(TAG_SERVICE_NAME, ""));
        pkt.add_tag(Tag::new(TAG_HOST_UNIQ, vec![0x01, 0x02, 0x03]));

        let encoded = pkt.encode();
        let decoded = PppoePacket::decode(&encoded).unwrap();

        assert_eq!(decoded.code, PADI);
        assert_eq!(decoded.session_id, 0);
        assert_eq!(decoded.tags.len(), 2);
        assert_eq!(decoded.tags[0].tag_type, TAG_SERVICE_NAME);
        assert_eq!(decoded.tags[1].tag_type, TAG_HOST_UNIQ);
        assert_eq!(decoded.tags[1].value, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_packet_encode_decode_pado() {
        let mut pkt = PppoePacket::new(PADO, 0);
        pkt.add_tag(Tag::from_str(TAG_AC_NAME, "punglios-ac-01"));
        pkt.add_tag(Tag::new(TAG_AC_COOKIE, vec![0xde, 0xad, 0xbe, 0xef]));
        pkt.add_tag(Tag::new(TAG_HOST_UNIQ, vec![0x01, 0x02, 0x03]));

        let encoded = pkt.encode();
        let decoded = PppoePacket::decode(&encoded).unwrap();

        assert_eq!(decoded.code, PADO);
        assert_eq!(decoded.find_tag_str(TAG_AC_NAME).unwrap(), "punglios-ac-01");
        assert_eq!(
            decoded.find_tag(TAG_AC_COOKIE).unwrap().value,
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_packet_decode_invalid_version() {
        let encoded = vec![0x20, PADI, 0, 0, 0, 0];
        let result = PppoePacket::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_decode_too_short() {
        let result = PppoePacket::decode(&[0x11, PADI]);
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_decode_too_short() {
        let result = Tag::decode(&[0x01, 0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_nonexistent_tag() {
        let pkt = PppoePacket::new(PADO, 0);
        assert!(pkt.find_tag(TAG_AC_COOKIE).is_none());
    }

    #[test]
    fn test_tag_map_groups_duplicates() {
        let mut pkt = PppoePacket::new(PADO, 0);
        pkt.add_tag(Tag::from_str(TAG_SERVICE_NAME, "isp-a"));
        pkt.add_tag(Tag::from_str(TAG_SERVICE_NAME, "isp-b"));
        let map = pkt.tag_map();
        let names = map.get(&TAG_SERVICE_NAME).unwrap();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_discovery_state_transitions() {
        let idle = DiscoveryState::Idle;
        assert!(!idle.is_connected());
        assert!(idle.session_id().is_none());

        let est = DiscoveryState::Established {
            session_id: 42,
            ac_name: "test-ac".into(),
        };
        assert!(est.is_connected());
        assert_eq!(est.session_id(), Some(42));
    }
}
