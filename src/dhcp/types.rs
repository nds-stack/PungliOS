use anyhow::{Result, bail};
use std::net::Ipv4Addr;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

pub const OP_BOOTREQUEST: u8 = 1;
pub const OP_BOOTREPLY: u8 = 2;

pub const HTYPE_ETHERNET: u8 = 1;
pub const HLEN_ETHERNET: u8 = 6;

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_DECLINE: u8 = 4;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
pub const DHCP_INFORM: u8 = 8;

pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS_SERVER: u8 = 6;
pub const OPT_HOST_NAME: u8 = 12;
pub const OPT_DOMAIN_NAME: u8 = 15;
pub const OPT_BROADCAST_ADDRESS: u8 = 28;
pub const OPT_IP_ADDRESS_LEASE_TIME: u8 = 51;
pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_IDENTIFIER: u8 = 54;
pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_CLIENT_IDENTIFIER: u8 = 61;
pub const OPT_END: u8 = 255;

pub const LEASE_DEFAULT_SECONDS: u32 = 86400;
pub const RENEWAL_TIME_RATIO: f64 = 0.5;
pub const REBINDING_TIME_RATIO: f64 = 0.875;

#[derive(Debug, Clone, PartialEq)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<DhcpOption>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DhcpOption {
    pub code: u8,
    pub value: Vec<u8>,
}

impl DhcpOption {
    pub fn new(code: u8, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    pub fn new_ip(code: u8, ip: Ipv4Addr) -> Self {
        Self {
            code,
            value: ip.octets().to_vec(),
        }
    }

    pub fn new_u32(code: u8, val: u32) -> Self {
        Self {
            code,
            value: val.to_be_bytes().to_vec(),
        }
    }

    pub fn new_byte(code: u8, val: u8) -> Self {
        Self {
            code,
            value: vec![val],
        }
    }

    pub fn as_ip(&self) -> Option<Ipv4Addr> {
        if self.value.len() >= 4 {
            Some(Ipv4Addr::new(
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ))
        } else {
            None
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }
}

impl DhcpPacket {
    pub fn new(op: u8) -> Self {
        Self {
            op,
            htype: HTYPE_ETHERNET,
            hlen: HLEN_ETHERNET,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![],
        }
    }

    pub fn magic_cookie() -> [u8; 4] {
        [99, 130, 83, 99]
    }

    pub fn find_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|o| o.code == code)
    }

    pub fn message_type(&self) -> Option<u8> {
        self.find_option(OPT_DHCP_MESSAGE_TYPE)
            .and_then(|o| o.value.first().copied())
    }

    pub fn client_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.find_option(OPT_SERVER_IDENTIFIER)
            .and_then(|o| o.as_ip())
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.find_option(50).and_then(|o| o.as_ip())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![self.op, self.htype, self.hlen, self.hops];
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.extend_from_slice(&self.sname);
        buf.extend_from_slice(&self.file);
        buf.extend_from_slice(&Self::magic_cookie());
        for opt in &self.options {
            if opt.code == OPT_END {
                buf.push(OPT_END);
                break;
            }
            buf.push(opt.code);
            buf.push(opt.value.len() as u8);
            buf.extend_from_slice(&opt.value);
        }
        buf.push(OPT_END);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 240 {
            bail!("DHCP packet too short: {} bytes", data.len());
        }
        let mut pkt = Self {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            secs: u16::from_be_bytes([data[8], data[9]]),
            flags: u16::from_be_bytes([data[10], data[11]]),
            ciaddr: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            yiaddr: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            siaddr: Ipv4Addr::new(data[20], data[21], data[22], data[23]),
            giaddr: Ipv4Addr::new(data[24], data[25], data[26], data[27]),
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![],
        };
        pkt.chaddr.copy_from_slice(&data[28..44]);
        pkt.sname.copy_from_slice(&data[44..108]);
        pkt.file.copy_from_slice(&data[108..236]);

        let mut offset = 240;
        while offset + 1 < data.len() {
            let code = data[offset];
            if code == OPT_END {
                break;
            }
            if code == 0 {
                offset += 1;
                continue;
            }
            if offset + 1 >= data.len() {
                break;
            }
            let len = data[offset + 1] as usize;
            if offset + 2 + len > data.len() {
                break;
            }
            let value = data[offset + 2..offset + 2 + len].to_vec();
            pkt.options.push(DhcpOption { code, value });
            offset += 2 + len;
        }
        Ok(pkt)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LeaseState {
    Free,
    Offered { xid: u32 },
    Allocated,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub state: LeaseState,
    pub allocated_at: u64,
    pub lease_seconds: u32,
    pub hostname: Option<String>,
}

impl Lease {
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.allocated_at + self.lease_seconds as u64
    }

    pub fn time_left(&self, now: u64) -> u32 {
        if self.is_expired(now) {
            0
        } else {
            (self.allocated_at + self.lease_seconds as u64 - now) as u32
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpPool {
    pub subnet: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub start_ip: Ipv4Addr,
    pub end_ip: Ipv4Addr,
    pub lease_seconds: u32,
}

impl IpPool {
    pub fn new(
        subnet: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Ipv4Addr,
        start_ip: Ipv4Addr,
        end_ip: Ipv4Addr,
    ) -> Self {
        Self {
            subnet,
            mask,
            gateway,
            dns_servers: vec![],
            start_ip,
            end_ip,
            lease_seconds: LEASE_DEFAULT_SECONDS,
        }
    }

    pub fn with_dns(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.dns_servers = servers;
        self
    }

    pub fn with_lease(mut self, seconds: u32) -> Self {
        self.lease_seconds = seconds;
        self
    }

    pub fn broadcast_address(&self) -> Ipv4Addr {
        let subnet_bits = u32::from(self.subnet);
        let mask_bits = u32::from(self.mask);
        let broadcast_bits = subnet_bits | !mask_bits;
        Ipv4Addr::from(broadcast_bits)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let start = u32::from(self.start_ip);
        let end = u32::from(self.end_ip);
        let ip_val = u32::from(ip);
        ip_val >= start && ip_val <= end
    }

    pub fn total_addresses(&self) -> u32 {
        let start = u32::from(self.start_ip);
        let end = u32::from(self.end_ip);
        end.saturating_sub(start) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_packet_encode_decode_discover() {
        let mut pkt = DhcpPacket::new(OP_BOOTREQUEST);
        pkt.xid = 0x12345678;
        pkt.chaddr[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_DISCOVER));
        pkt.options.push(DhcpOption::new(
            OPT_PARAMETER_REQUEST_LIST,
            vec![1, 3, 6, 15],
        ));

        let encoded = pkt.encode();
        let decoded = DhcpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.op, OP_BOOTREQUEST);
        assert_eq!(decoded.xid, 0x12345678);
        assert_eq!(decoded.client_mac(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(decoded.message_type(), Some(DHCP_DISCOVER));
    }

    #[test]
    fn test_dhcp_packet_encode_decode_offer() {
        let mut pkt = DhcpPacket::new(OP_BOOTREPLY);
        pkt.xid = 0x87654321;
        pkt.yiaddr = Ipv4Addr::new(192, 168, 1, 100);
        pkt.chaddr[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_OFFER));
        pkt.options.push(DhcpOption::new_ip(
            OPT_SUBNET_MASK,
            Ipv4Addr::new(255, 255, 255, 0),
        ));
        pkt.options.push(DhcpOption::new_ip(
            OPT_ROUTER,
            Ipv4Addr::new(192, 168, 1, 1),
        ));
        pkt.options.push(DhcpOption::new_ip(
            OPT_DNS_SERVER,
            Ipv4Addr::new(8, 8, 8, 8),
        ));
        pkt.options.push(DhcpOption::new_ip(
            OPT_SERVER_IDENTIFIER,
            Ipv4Addr::new(192, 168, 1, 1),
        ));
        pkt.options
            .push(DhcpOption::new_u32(OPT_IP_ADDRESS_LEASE_TIME, 86400));

        let encoded = pkt.encode();
        let decoded = DhcpPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.op, OP_BOOTREPLY);
        assert_eq!(decoded.message_type(), Some(DHCP_OFFER));
        assert_eq!(decoded.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(
            decoded
                .find_option(OPT_SUBNET_MASK)
                .unwrap()
                .as_ip()
                .unwrap(),
            Ipv4Addr::new(255, 255, 255, 0)
        );
        assert!(decoded.server_id().is_some());
    }

    #[test]
    fn test_ip_pool_contains() {
        let pool = IpPool::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
        );
        assert!(pool.contains(Ipv4Addr::new(192, 168, 1, 150)));
        assert!(!pool.contains(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!pool.contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pool.total_addresses(), 101);
    }

    #[test]
    fn test_lease_expiry() {
        let lease = Lease {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            mac: [0xaa; 6],
            state: LeaseState::Allocated,
            allocated_at: 1000,
            lease_seconds: 3600,
            hostname: None,
        };
        assert!(!lease.is_expired(4000));
        assert!(lease.is_expired(5000));
    }

    #[test]
    fn test_dhcp_packet_decode_too_short() {
        let result = DhcpPacket::decode(&[0; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_broadcast_address() {
        let pool = IpPool::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
        );
        assert_eq!(pool.broadcast_address(), Ipv4Addr::new(192, 168, 1, 255));
    }
}
