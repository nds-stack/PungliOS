pub mod types;

use anyhow::{Result, bail};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use types::*;

pub struct DhcpServer {
    pub pool: IpPool,
    pub server_ip: Ipv4Addr,
    leases: HashMap<[u8; 6], Lease>,
    ip_leases: HashMap<Ipv4Addr, [u8; 6]>,
    reserved_ips: HashMap<[u8; 6], Ipv4Addr>,
}

impl DhcpServer {
    pub fn new(pool: IpPool, server_ip: Ipv4Addr) -> Self {
        Self {
            pool,
            server_ip,
            leases: HashMap::new(),
            ip_leases: HashMap::new(),
            reserved_ips: HashMap::new(),
        }
    }

    pub fn reserve_ip(&mut self, mac: [u8; 6], ip: Ipv4Addr) -> Result<()> {
        if !self.pool.contains(ip) {
            bail!("IP {ip} is outside pool range");
        }
        self.reserved_ips.insert(mac, ip);
        Ok(())
    }

    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }

    pub fn active_leases(&self) -> &HashMap<[u8; 6], Lease> {
        &self.leases
    }

    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn cleanup_expired(&mut self) {
        let now = self.now_seconds();
        let expired: Vec<[u8; 6]> = self
            .leases
            .iter()
            .filter(|(_, l)| l.is_expired(now))
            .map(|(mac, _)| *mac)
            .collect();
        for mac in expired {
            if let Some(lease) = self.leases.remove(&mac) {
                self.ip_leases.remove(&lease.ip);
            }
        }
    }

    fn allocate_ip(&mut self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        self.cleanup_expired();

        if let Some(ip) = self.reserved_ips.get(&mac)
            && !self.ip_leases.contains_key(ip)
        {
            return Some(*ip);
        }

        if let Some(lease) = self.leases.get(&mac) {
            return Some(lease.ip);
        }

        let start = u32::from(self.pool.start_ip);
        let end = u32::from(self.pool.end_ip);
        for ip_val in start..=end {
            let ip = Ipv4Addr::from(ip_val);
            if !self.ip_leases.contains_key(&ip) {
                return Some(ip);
            }
        }
        None
    }

    fn create_lease(&mut self, mac: [u8; 6], ip: Ipv4Addr, xid: u32) {
        let lease = Lease {
            ip,
            mac,
            state: LeaseState::Offered { xid },
            allocated_at: self.now_seconds(),
            lease_seconds: self.pool.lease_seconds,
            hostname: None,
        };
        self.leases.insert(mac, lease);
        self.ip_leases.insert(ip, mac);
    }

    fn confirm_lease(&mut self, mac: [u8; 6]) {
        let now = self.now_seconds();
        if let Some(lease) = self.leases.get_mut(&mac) {
            lease.state = LeaseState::Allocated;
            lease.allocated_at = now;
        }
    }

    fn release_lease(&mut self, mac: [u8; 6]) {
        if let Some(lease) = self.leases.remove(&mac) {
            self.ip_leases.remove(&lease.ip);
        }
    }

    pub fn handle_discover(&mut self, pkt: &DhcpPacket) -> DhcpPacket {
        let mac = pkt.client_mac();
        let requested_ip = pkt.requested_ip().filter(|ip| self.pool.contains(*ip));

        let ip = requested_ip
            .or_else(|| self.allocate_ip(mac))
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        if ip == Ipv4Addr::UNSPECIFIED {
            return DhcpPacket::new(OP_BOOTREPLY);
        }

        self.create_lease(mac, ip, pkt.xid);
        self.build_offer(pkt, ip)
    }

    pub fn handle_request(&mut self, pkt: &DhcpPacket) -> DhcpPacket {
        let mac = pkt.client_mac();
        let requested_ip = pkt.requested_ip();
        let server_id = pkt.server_id();

        if let Some(sid) = server_id
            && sid != self.server_ip
        {
            return DhcpPacket::new(OP_BOOTREPLY);
        }

        match requested_ip {
            Some(ip) if self.pool.contains(ip) => {
                let existing = self.leases.get(&mac);
                match existing {
                    Some(lease)
                        if lease.ip == ip && matches!(lease.state, LeaseState::Offered { .. }) =>
                    {
                        self.confirm_lease(mac);
                        self.build_ack(pkt, ip)
                    }
                    Some(lease)
                        if lease.ip == ip && matches!(lease.state, LeaseState::Allocated) =>
                    {
                        self.confirm_lease(mac);
                        self.build_ack(pkt, ip)
                    }
                    _ => {
                        if self.ip_leases.contains_key(&ip) && self.ip_leases.get(&ip) != Some(&mac)
                        {
                            self.build_nak(pkt)
                        } else {
                            self.create_lease(mac, ip, pkt.xid);
                            self.confirm_lease(mac);
                            self.build_ack(pkt, ip)
                        }
                    }
                }
            }
            _ => self.build_nak(pkt),
        }
    }

    pub fn handle_release(&mut self, pkt: &DhcpPacket) {
        let mac = pkt.client_mac();
        self.release_lease(mac);
    }

    fn build_offer(&self, discover: &DhcpPacket, offered_ip: Ipv4Addr) -> DhcpPacket {
        let mut reply = DhcpPacket::new(OP_BOOTREPLY);
        reply.xid = discover.xid;
        reply.yiaddr = offered_ip;
        reply.siaddr = self.server_ip;
        reply.chaddr = discover.chaddr;
        reply.flags = discover.flags;
        reply
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_OFFER));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_SERVER_IDENTIFIER, self.server_ip));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_SUBNET_MASK, self.pool.mask));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_ROUTER, self.pool.gateway));
        reply.options.push(DhcpOption::new_ip(
            OPT_BROADCAST_ADDRESS,
            self.pool.broadcast_address(),
        ));
        for dns in &self.pool.dns_servers {
            reply.options.push(DhcpOption::new_ip(OPT_DNS_SERVER, *dns));
        }
        reply.options.push(DhcpOption::new_u32(
            OPT_IP_ADDRESS_LEASE_TIME,
            self.pool.lease_seconds,
        ));
        reply.options.push(DhcpOption::new_u32(
            OPT_RENEWAL_TIME,
            (self.pool.lease_seconds as f64 * RENEWAL_TIME_RATIO) as u32,
        ));
        reply.options.push(DhcpOption::new_u32(
            OPT_REBINDING_TIME,
            (self.pool.lease_seconds as f64 * REBINDING_TIME_RATIO) as u32,
        ));
        reply
    }

    fn build_ack(&self, request: &DhcpPacket, ack_ip: Ipv4Addr) -> DhcpPacket {
        let mut reply = DhcpPacket::new(OP_BOOTREPLY);
        reply.xid = request.xid;
        reply.yiaddr = ack_ip;
        reply.siaddr = self.server_ip;
        reply.chaddr = request.chaddr;
        reply.flags = request.flags;
        reply
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_ACK));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_SERVER_IDENTIFIER, self.server_ip));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_SUBNET_MASK, self.pool.mask));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_ROUTER, self.pool.gateway));
        reply.options.push(DhcpOption::new_ip(
            OPT_BROADCAST_ADDRESS,
            self.pool.broadcast_address(),
        ));
        for dns in &self.pool.dns_servers {
            reply.options.push(DhcpOption::new_ip(OPT_DNS_SERVER, *dns));
        }
        reply.options.push(DhcpOption::new_u32(
            OPT_IP_ADDRESS_LEASE_TIME,
            self.pool.lease_seconds,
        ));
        reply.options.push(DhcpOption::new_u32(
            OPT_RENEWAL_TIME,
            (self.pool.lease_seconds as f64 * RENEWAL_TIME_RATIO) as u32,
        ));
        reply.options.push(DhcpOption::new_u32(
            OPT_REBINDING_TIME,
            (self.pool.lease_seconds as f64 * REBINDING_TIME_RATIO) as u32,
        ));
        reply
    }

    fn build_nak(&self, request: &DhcpPacket) -> DhcpPacket {
        let mut reply = DhcpPacket::new(OP_BOOTREPLY);
        reply.xid = request.xid;
        reply.chaddr = request.chaddr;
        reply
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_NAK));
        reply
            .options
            .push(DhcpOption::new_ip(OPT_SERVER_IDENTIFIER, self.server_ip));
        reply
    }

    pub fn handle_packet(&mut self, pkt: &DhcpPacket) -> Option<DhcpPacket> {
        match pkt.message_type() {
            Some(DHCP_DISCOVER) => {
                if pkt.op != OP_BOOTREQUEST {
                    return None;
                }
                Some(self.handle_discover(pkt))
            }
            Some(DHCP_REQUEST) => {
                if pkt.op != OP_BOOTREQUEST {
                    return None;
                }
                Some(self.handle_request(pkt))
            }
            Some(DHCP_RELEASE) => {
                self.handle_release(pkt);
                None
            }
            Some(DHCP_DECLINE) => {
                if let Some(ip) = pkt.requested_ip() {
                    self.ip_leases.remove(&ip);
                    let mac = pkt.client_mac();
                    self.leases.remove(&mac);
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> IpPool {
        IpPool::new(
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
        )
        .with_dns(vec![Ipv4Addr::new(8, 8, 8, 8)])
    }

    fn make_discover(mac: [u8; 6], xid: u32) -> DhcpPacket {
        let mut pkt = DhcpPacket::new(OP_BOOTREQUEST);
        pkt.xid = xid;
        pkt.chaddr[..6].copy_from_slice(&mac);
        pkt.options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_DISCOVER));
        pkt
    }

    fn make_request(mac: [u8; 6], xid: u32, ip: Ipv4Addr, server_id: Ipv4Addr) -> DhcpPacket {
        let mut pkt = DhcpPacket::new(OP_BOOTREQUEST);
        pkt.xid = xid;
        pkt.chaddr[..6].copy_from_slice(&mac);
        pkt.options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_REQUEST));
        pkt.options.push(DhcpOption::new_ip(50, ip));
        pkt.options
            .push(DhcpOption::new_ip(OPT_SERVER_IDENTIFIER, server_id));
        pkt
    }

    #[test]
    fn test_discover_offer_flow() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let discover = make_discover(mac, 0x1000);

        let offer = server.handle_discover(&discover);
        assert_eq!(offer.message_type(), Some(DHCP_OFFER));
        assert!(!offer.yiaddr.is_unspecified());
        assert!(test_pool().contains(offer.yiaddr));
    }

    #[test]
    fn test_full_dora_flow() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // Discover
        let discover = make_discover(mac, 0x1000);
        let offer = server.handle_discover(&discover);
        let offered_ip = offer.yiaddr;
        assert_eq!(offer.message_type(), Some(DHCP_OFFER));

        // Request
        let request = make_request(mac, 0x1001, offered_ip, Ipv4Addr::new(192, 168, 1, 1));
        let ack = server.handle_request(&request);
        assert_eq!(ack.message_type(), Some(DHCP_ACK));
        assert_eq!(ack.yiaddr, offered_ip);

        // Verify lease
        assert_eq!(server.lease_count(), 1);
        let lease = server.leases.get(&mac).unwrap();
        assert_eq!(lease.state, LeaseState::Allocated);
        assert_eq!(lease.ip, offered_ip);
    }

    #[test]
    fn test_dhcp_nak_for_wrong_server() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // Request to wrong server
        let request = make_request(
            mac,
            0x1000,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 2, 1),
        );
        let response = server.handle_request(&request);
        assert_eq!(response.op, OP_BOOTREPLY);
        assert_eq!(response.options.len(), 0);
    }

    #[test]
    fn test_dhcp_nak_for_invalid_ip() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // Request an IP outside pool
        let request = make_request(
            mac,
            0x1000,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
        );
        let nak = server.handle_request(&request);
        assert_eq!(nak.message_type(), Some(DHCP_NAK));
    }

    #[test]
    fn test_dhcp_release() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // DORA
        let offer = server.handle_discover(&make_discover(mac, 0x1000));
        server.handle_request(&make_request(
            mac,
            0x1001,
            offer.yiaddr,
            Ipv4Addr::new(192, 168, 1, 1),
        ));
        assert_eq!(server.lease_count(), 1);

        // Release
        let mut release = DhcpPacket::new(OP_BOOTREQUEST);
        release.chaddr[..6].copy_from_slice(&mac);
        release
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_RELEASE));
        server.handle_release(&release);
        assert_eq!(server.lease_count(), 0);
    }

    #[test]
    fn test_multiple_clients_get_different_ips() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mut used_ips = Vec::new();

        for i in 0..5 {
            let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, i];
            let discover = make_discover(mac, 0x1000 + i as u32);
            let offer = server.handle_discover(&discover);
            let offered_ip = offer.yiaddr;
            assert!(!offered_ip.is_unspecified(), "client {i} should get an IP");
            assert!(
                !used_ips.contains(&offered_ip),
                "IP {offered_ip} should be unique"
            );

            let request = make_request(
                mac,
                0x2000 + i as u32,
                offered_ip,
                Ipv4Addr::new(192, 168, 1, 1),
            );
            let ack = server.handle_request(&request);
            assert_eq!(ack.message_type(), Some(DHCP_ACK));

            used_ips.push(offered_ip);
        }
        assert_eq!(server.lease_count(), 5);
    }

    #[test]
    fn test_reserved_ip() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        server
            .reserve_ip(mac, Ipv4Addr::new(192, 168, 1, 150))
            .unwrap();

        let discover = make_discover(mac, 0x1000);
        let offer = server.handle_discover(&discover);
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 150));
    }

    #[test]
    fn test_reserved_ip_outside_pool_rejected() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let result = server.reserve_ip(mac, Ipv4Addr::new(10, 0, 0, 1));
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_packet_routes_correctly() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // Discover via handle_packet
        let discover = make_discover(mac, 0x1000);
        let offer = server.handle_packet(&discover).unwrap();
        assert_eq!(offer.message_type(), Some(DHCP_OFFER));

        // Request via handle_packet
        let request = make_request(mac, 0x1001, offer.yiaddr, Ipv4Addr::new(192, 168, 1, 1));
        let ack = server.handle_packet(&request).unwrap();
        assert_eq!(ack.message_type(), Some(DHCP_ACK));

        // Release via handle_packet — returns None
        let mut release = DhcpPacket::new(OP_BOOTREQUEST);
        release.chaddr[..6].copy_from_slice(&mac);
        release
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_RELEASE));
        let result = server.handle_packet(&release);
        assert!(result.is_none());
    }

    #[test]
    fn test_pool_lease_time_options() {
        let pool = test_pool().with_lease(7200);
        let mut server = DhcpServer::new(pool, Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa; 6];

        let discover = make_discover(mac, 0x1000);
        let offer = server.handle_discover(&discover);
        let lease_time = offer
            .find_option(OPT_IP_ADDRESS_LEASE_TIME)
            .and_then(|o| o.as_u32());
        assert_eq!(lease_time, Some(7200));
    }

    #[test]
    fn test_decline_frees_ip() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa; 6];

        let offer = server.handle_discover(&make_discover(mac, 0x1000));
        let ip = offer.yiaddr;
        server.handle_request(&make_request(
            mac,
            0x1001,
            ip,
            Ipv4Addr::new(192, 168, 1, 1),
        ));
        assert_eq!(server.lease_count(), 1);

        // Client declines
        let mut decline = DhcpPacket::new(OP_BOOTREQUEST);
        decline.xid = 0x1002;
        decline.chaddr[..6].copy_from_slice(&mac);
        decline
            .options
            .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_DECLINE));
        decline.options.push(DhcpOption::new_ip(50, ip));
        let result = server.handle_packet(&decline);
        assert!(result.is_none());
        assert_eq!(server.lease_count(), 0);
    }

    #[test]
    fn test_client_retains_ip_on_reboot() {
        let mut server = DhcpServer::new(test_pool(), Ipv4Addr::new(192, 168, 1, 1));
        let mac = [0xaa; 6];

        // First time — gets an IP
        let offer1 = server.handle_discover(&make_discover(mac, 0x1000));
        let ip1 = offer1.yiaddr;
        server.handle_request(&make_request(
            mac,
            0x1001,
            ip1,
            Ipv4Addr::new(192, 168, 1, 1),
        ));
        assert_eq!(server.lease_count(), 1);

        // Reboot — should get same IP (existing lease)
        let offer2 = server.handle_discover(&make_discover(mac, 0x2000));
        assert_eq!(offer2.yiaddr, ip1);
    }
}
