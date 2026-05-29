use anyhow::{Result, bail};
use md5::{Digest, Md5};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

pub const RADIUS_PORT: u16 = 1812;
pub const RADIUS_ACCT_PORT: u16 = 1813;

pub const ACCESS_REQUEST: u8 = 1;
pub const ACCESS_ACCEPT: u8 = 2;
pub const ACCESS_REJECT: u8 = 3;
pub const ACCOUNTING_REQUEST: u8 = 4;
pub const ACCOUNTING_RESPONSE: u8 = 5;
pub const ACCESS_CHALLENGE: u8 = 11;

pub const ATTR_USER_NAME: u8 = 1;
pub const ATTR_USER_PASSWORD: u8 = 2;
pub const ATTR_CHAP_PASSWORD: u8 = 3;
pub const ATTR_NAS_IP_ADDRESS: u8 = 4;
pub const ATTR_NAS_PORT: u8 = 5;
pub const ATTR_SERVICE_TYPE: u8 = 6;
pub const ATTR_FRAMED_PROTOCOL: u8 = 7;
pub const ATTR_FRAMED_IP_ADDRESS: u8 = 8;
pub const ATTR_FRAMED_IP_NETMASK: u8 = 9;
pub const ATTR_FILTER_ID: u8 = 11;
pub const ATTR_FRAMED_MTU: u8 = 12;
pub const ATTR_SESSION_TIMEOUT: u8 = 27;
pub const ATTR_CALLED_STATION_ID: u8 = 30;
pub const ATTR_CALLING_STATION_ID: u8 = 31;
pub const ATTR_NAS_IDENTIFIER: u8 = 32;
pub const ATTR_ACCT_STATUS_TYPE: u8 = 40;
pub const ATTR_ACCT_DELAY_TIME: u8 = 41;
pub const ATTR_ACCT_INPUT_OCTETS: u8 = 42;
pub const ATTR_ACCT_OUTPUT_OCTETS: u8 = 43;
pub const ATTR_ACCT_SESSION_ID: u8 = 44;
pub const ATTR_ACCT_AUTHENTIC: u8 = 45;
pub const ATTR_ACCT_SESSION_TIME: u8 = 46;
pub const ATTR_ACCT_INPUT_PACKETS: u8 = 47;
pub const ATTR_ACCT_OUTPUT_PACKETS: u8 = 48;
pub const ATTR_ACCT_TERMINATE_CAUSE: u8 = 49;
pub const ATTR_ACCT_INPUT_GIGAWORDS: u8 = 52;
pub const ATTR_ACCT_OUTPUT_GIGAWORDS: u8 = 53;
pub const ATTR_CHAP_CHALLENGE: u8 = 60;
pub const ATTR_NAS_PORT_TYPE: u8 = 61;
pub const ATTR_TUNNEL_TYPE: u8 = 64;
pub const ATTR_TUNNEL_MEDIUM_TYPE: u8 = 65;
pub const ATTR_TUNNEL_CLIENT_ENDPOINT: u8 = 66;

pub const SERVICE_LOGIN: u32 = 1;
pub const SERVICE_FRAMED: u32 = 2;

pub const FRAMED_PPP: u32 = 1;

pub const ACCT_STATUS_START: u32 = 1;
pub const ACCT_STATUS_STOP: u32 = 2;
pub const ACCT_STATUS_INTERIM_UPDATE: u32 = 3;

pub const AUTHENTIC_RADIUS: u32 = 1;

pub const TERMINATE_USER_REQUEST: u32 = 1;
pub const TERMINATE_LOST_CARRIER: u32 = 2;
pub const TERMINATE_SESSION_TIMEOUT: u32 = 5;
pub const TERMINATE_ADMIN_RESET: u32 = 6;

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attr_type: u8,
    pub value: Vec<u8>,
}

impl RadiusAttribute {
    pub fn new_string(attr_type: u8, s: &str) -> Self {
        Self {
            attr_type,
            value: s.as_bytes().to_vec(),
        }
    }

    pub fn new_u32(attr_type: u8, val: u32) -> Self {
        Self {
            attr_type,
            value: val.to_be_bytes().to_vec(),
        }
    }

    pub fn new_ip(attr_type: u8, ip: Ipv4Addr) -> Self {
        Self {
            attr_type,
            value: ip.octets().to_vec(),
        }
    }

    pub fn new_bytes(attr_type: u8, value: Vec<u8>) -> Self {
        Self { attr_type, value }
    }

    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
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

    pub fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![self.attr_type];
        buf.push((self.value.len() + 2) as u8);
        buf.extend_from_slice(&self.value);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 2 {
            bail!("attribute too short");
        }
        let attr_type = data[0];
        let len = data[1] as usize;
        if len < 2 || data.len() < len {
            bail!("attribute length mismatch: {len} vs {}", data.len());
        }
        let value = data[2..len].to_vec();
        Ok((Self { attr_type, value }, len))
    }
}

#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

impl RadiusPacket {
    pub fn new(code: u8, identifier: u8) -> Self {
        Self {
            code,
            identifier,
            authenticator: [0u8; 16],
            attributes: vec![],
        }
    }

    pub fn code_name(code: u8) -> &'static str {
        match code {
            ACCESS_REQUEST => "Access-Request",
            ACCESS_ACCEPT => "Access-Accept",
            ACCESS_REJECT => "Access-Reject",
            ACCOUNTING_REQUEST => "Accounting-Request",
            ACCOUNTING_RESPONSE => "Accounting-Response",
            ACCESS_CHALLENGE => "Access-Challenge",
            _ => "Unknown",
        }
    }

    pub fn find_attr(&self, attr_type: u8) -> Option<&RadiusAttribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }

    pub fn find_attr_string(&self, attr_type: u8) -> Option<String> {
        self.find_attr(attr_type).and_then(|a| a.as_string())
    }

    pub fn find_attr_u32(&self, attr_type: u8) -> Option<u32> {
        self.find_attr(attr_type).and_then(|a| a.as_u32())
    }

    pub fn find_attr_ip(&self, attr_type: u8) -> Option<Ipv4Addr> {
        self.find_attr(attr_type).and_then(|a| a.as_ip())
    }

    pub fn encode(&self) -> Vec<u8> {
        let attrs_len: usize = self.attributes.iter().map(|a| a.encoded_len()).sum();
        let total_len = 20 + attrs_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.push(self.code);
        buf.push(self.identifier);
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.extend_from_slice(&self.authenticator);
        for attr in &self.attributes {
            buf.extend_from_slice(&attr.encode());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            bail!("RADIUS packet too short: {} bytes", data.len());
        }
        let code = data[0];
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < length {
            bail!(
                "RADIUS packet truncated: have {}, need {}",
                data.len(),
                length
            );
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);

        let mut attributes = Vec::new();
        let mut offset = 20;
        while offset + 2 <= length {
            if data[offset] == 0 {
                break;
            }
            let (attr, consumed) = RadiusAttribute::decode(&data[offset..length])?;
            offset += consumed;
            attributes.push(attr);
        }

        Ok(Self {
            code,
            identifier,
            authenticator,
            attributes,
        })
    }
}

pub trait RadiusBackend: Send + Sync {
    fn send_request(&self, packet: &RadiusPacket) -> Result<RadiusPacket>;
    fn send_accounting(&self, packet: &RadiusPacket) -> Result<RadiusPacket>;
}

#[derive(Clone)]
pub struct MockRadiusBackend {
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    #[allow(dead_code)]
    secret: String,
    #[allow(dead_code)]
    nas_identifier: String,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub username: String,
    pub password: String,
    pub ip_address: Option<Ipv4Addr>,
    pub bandwidth_up: Option<u64>,
    pub bandwidth_down: Option<u64>,
    pub session_timeout: Option<u32>,
    pub allowed: bool,
}

impl UserRecord {
    pub fn new(username: &str, password: &str, allowed: bool) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            ip_address: None,
            bandwidth_up: None,
            bandwidth_down: None,
            session_timeout: None,
            allowed,
        }
    }
}

impl MockRadiusBackend {
    pub fn new(secret: &str, nas_identifier: &str) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            secret: secret.into(),
            nas_identifier: nas_identifier.into(),
        }
    }

    pub fn add_user(&self, record: UserRecord) {
        self.users
            .write()
            .expect("lock poisoned")
            .insert(record.username.clone(), record);
    }

    pub fn user_count(&self) -> usize {
        self.users.read().expect("lock poisoned").len()
    }
}

impl RadiusBackend for MockRadiusBackend {
    fn send_request(&self, packet: &RadiusPacket) -> Result<RadiusPacket> {
        let username = packet.find_attr_string(ATTR_USER_NAME).unwrap_or_default();
        let users = self.users.read().expect("lock poisoned");

        let user = users
            .get(&username)
            .ok_or_else(|| anyhow::anyhow!("user '{username}' not found"))?;

        let mut response = RadiusPacket::new(
            if user.allowed {
                ACCESS_ACCEPT
            } else {
                ACCESS_REJECT
            },
            packet.identifier,
        );

        if user.allowed {
            if let Some(ip) = user.ip_address {
                response
                    .attributes
                    .push(RadiusAttribute::new_ip(ATTR_FRAMED_IP_ADDRESS, ip));
            }
            response
                .attributes
                .push(RadiusAttribute::new_u32(ATTR_SERVICE_TYPE, SERVICE_FRAMED));
            response
                .attributes
                .push(RadiusAttribute::new_u32(ATTR_FRAMED_PROTOCOL, FRAMED_PPP));
            response
                .attributes
                .push(RadiusAttribute::new_u32(ATTR_FRAMED_MTU, 1492));
            if let Some(timeout) = user.session_timeout {
                response
                    .attributes
                    .push(RadiusAttribute::new_u32(ATTR_SESSION_TIMEOUT, timeout));
            }
        }

        Ok(response)
    }

    fn send_accounting(&self, packet: &RadiusPacket) -> Result<RadiusPacket> {
        let response = RadiusPacket::new(ACCOUNTING_RESPONSE, packet.identifier);
        Ok(response)
    }
}

/// Encrypt RADIUS password per RFC 2865 Section 5.2.
///
/// Uses MD5 XOR block cipher with the shared secret:
/// - Block 1: MD5(secret + Request Authenticator) XOR password[0..16]
/// - Block N: MD5(secret + encrypted[N-1]) XOR password[N*16..(N+1)*16]
fn encrypt_radius_password(
    password: &str,
    secret: &str,
    authenticator: &[u8; 16],
) -> Result<Vec<u8>> {
    if password.len() > 128 {
        bail!("RADIUS password exceeds 128 byte limit");
    }
    if secret.is_empty() {
        bail!("RADIUS shared secret is empty");
    }

    let pw_bytes = password.as_bytes();
    let block_count = pw_bytes.len().div_ceil(16);
    let padded_len = block_count * 16;
    let mut padded = pw_bytes.to_vec();
    padded.resize(padded_len, 0);

    let mut encrypted = Vec::with_capacity(padded_len);
    let mut prev = authenticator.to_vec();

    for chunk in padded.chunks(16) {
        let mut hasher = Md5::new();
        hasher.update(secret.as_bytes());
        hasher.update(&prev);
        let hash = hasher.finalize();

        let enc: Vec<u8> = chunk.iter().zip(hash.iter()).map(|(a, b)| a ^ b).collect();
        encrypted.extend_from_slice(&enc);
        prev = enc;
    }

    Ok(encrypted)
}

pub struct RadiusClient<B: RadiusBackend> {
    backend: B,
    nas_ip: Ipv4Addr,
    nas_identifier: String,
    secret: String,
    auth_port: u16,
    acct_port: u16,
    next_identifier: u8,
}

impl<B: RadiusBackend> RadiusClient<B> {
    pub fn new(backend: B, nas_ip: Ipv4Addr, nas_identifier: &str, secret: &str) -> Self {
        Self {
            backend,
            nas_ip,
            nas_identifier: nas_identifier.into(),
            secret: secret.into(),
            auth_port: RADIUS_PORT,
            acct_port: RADIUS_ACCT_PORT,
            next_identifier: 0,
        }
    }

    pub fn with_ports(mut self, auth_port: u16, acct_port: u16) -> Self {
        self.auth_port = auth_port;
        self.acct_port = acct_port;
        self
    }

    fn next_id(&mut self) -> u8 {
        let id = self.next_identifier;
        self.next_identifier = self.next_identifier.wrapping_add(1);
        id
    }

    pub fn authenticate(
        &mut self,
        username: &str,
        password: &str,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        let mut req = RadiusPacket::new(ACCESS_REQUEST, self.next_id());
        req.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_NAME, username));
        req.attributes.push(RadiusAttribute::new_bytes(
            ATTR_USER_PASSWORD,
            encrypt_radius_password(password, &self.secret, &req.authenticator)?,
        ));
        req.attributes
            .push(RadiusAttribute::new_ip(ATTR_NAS_IP_ADDRESS, self.nas_ip));
        req.attributes
            .push(RadiusAttribute::new_u32(ATTR_NAS_PORT, 0));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_CALLING_STATION_ID,
            calling_station_id,
        ));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_NAS_IDENTIFIER,
            &self.nas_identifier,
        ));
        req.attributes
            .push(RadiusAttribute::new_u32(ATTR_SERVICE_TYPE, SERVICE_FRAMED));

        self.backend.send_request(&req)
    }

    pub fn accounting_start(
        &mut self,
        username: &str,
        session_id: &str,
        framed_ip: Option<Ipv4Addr>,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        let mut req = RadiusPacket::new(ACCOUNTING_REQUEST, self.next_id());
        req.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_NAME, username));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_ACCT_SESSION_ID,
            session_id,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_STATUS_TYPE,
            ACCT_STATUS_START,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_AUTHENTIC,
            AUTHENTIC_RADIUS,
        ));
        req.attributes
            .push(RadiusAttribute::new_ip(ATTR_NAS_IP_ADDRESS, self.nas_ip));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_CALLING_STATION_ID,
            calling_station_id,
        ));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_NAS_IDENTIFIER,
            &self.nas_identifier,
        ));
        if let Some(ip) = framed_ip {
            req.attributes
                .push(RadiusAttribute::new_ip(ATTR_FRAMED_IP_ADDRESS, ip));
        }

        self.backend.send_accounting(&req)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accounting_stop(
        &mut self,
        username: &str,
        session_id: &str,
        input_octets: u64,
        output_octets: u64,
        session_time: u32,
        input_packets: u64,
        output_packets: u64,
        terminate_cause: u32,
        framed_ip: Option<Ipv4Addr>,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        let mut req = RadiusPacket::new(ACCOUNTING_REQUEST, self.next_id());
        req.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_NAME, username));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_ACCT_SESSION_ID,
            session_id,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_STATUS_TYPE,
            ACCT_STATUS_STOP,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_AUTHENTIC,
            AUTHENTIC_RADIUS,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_TERMINATE_CAUSE,
            terminate_cause,
        ));
        req.attributes
            .push(RadiusAttribute::new_ip(ATTR_NAS_IP_ADDRESS, self.nas_ip));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_NAS_IDENTIFIER,
            &self.nas_identifier,
        ));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_CALLING_STATION_ID,
            calling_station_id,
        ));
        if let Some(ip) = framed_ip {
            req.attributes
                .push(RadiusAttribute::new_ip(ATTR_FRAMED_IP_ADDRESS, ip));
        }

        let input_bytes = (input_octets & 0xFFFFFFFF) as u32;
        let output_bytes = (output_octets & 0xFFFFFFFF) as u32;
        if input_octets > 0xFFFFFFFF {
            req.attributes.push(RadiusAttribute::new_u32(
                ATTR_ACCT_INPUT_GIGAWORDS,
                (input_octets >> 32) as u32,
            ));
        }
        if output_octets > 0xFFFFFFFF {
            req.attributes.push(RadiusAttribute::new_u32(
                ATTR_ACCT_OUTPUT_GIGAWORDS,
                (output_octets >> 32) as u32,
            ));
        }
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_INPUT_OCTETS,
            input_bytes,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_OUTPUT_OCTETS,
            output_bytes,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_SESSION_TIME,
            session_time,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_INPUT_PACKETS,
            input_packets as u32,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_OUTPUT_PACKETS,
            output_packets as u32,
        ));

        self.backend.send_accounting(&req)
    }

    pub fn accounting_interim(
        &mut self,
        username: &str,
        session_id: &str,
        input_octets: u64,
        output_octets: u64,
        session_time: u32,
        framed_ip: Option<Ipv4Addr>,
    ) -> Result<RadiusPacket> {
        let mut req = RadiusPacket::new(ACCOUNTING_REQUEST, self.next_id());
        req.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_NAME, username));
        req.attributes.push(RadiusAttribute::new_string(
            ATTR_ACCT_SESSION_ID,
            session_id,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_STATUS_TYPE,
            ACCT_STATUS_INTERIM_UPDATE,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_AUTHENTIC,
            AUTHENTIC_RADIUS,
        ));
        req.attributes
            .push(RadiusAttribute::new_ip(ATTR_NAS_IP_ADDRESS, self.nas_ip));

        if let Some(ip) = framed_ip {
            req.attributes
                .push(RadiusAttribute::new_ip(ATTR_FRAMED_IP_ADDRESS, ip));
        }

        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_INPUT_OCTETS,
            (input_octets & 0xFFFFFFFF) as u32,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_OUTPUT_OCTETS,
            (output_octets & 0xFFFFFFFF) as u32,
        ));
        req.attributes.push(RadiusAttribute::new_u32(
            ATTR_ACCT_SESSION_TIME,
            session_time,
        ));

        self.backend.send_accounting(&req)
    }
}

pub struct RadiusSessionManager<B: RadiusBackend> {
    client: RadiusClient<B>,
    active_sessions: HashMap<String, RadiusSessionState>,
}

#[derive(Debug, Clone)]
pub struct RadiusSessionState {
    pub username: String,
    pub session_id: String,
    pub framed_ip: Option<Ipv4Addr>,
    pub session_time: u32,
    pub input_octets: u64,
    pub output_octets: u64,
    pub input_packets: u64,
    pub output_packets: u64,
    pub acct_started: bool,
}

impl<B: RadiusBackend> RadiusSessionManager<B> {
    pub fn new(client: RadiusClient<B>) -> Self {
        Self {
            client,
            active_sessions: HashMap::new(),
        }
    }

    pub fn active_sessions(&self) -> &HashMap<String, RadiusSessionState> {
        &self.active_sessions
    }

    pub fn authenticate(
        &mut self,
        username: &str,
        password: &str,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        self.client
            .authenticate(username, password, calling_station_id)
    }

    pub fn start_accounting(
        &mut self,
        username: &str,
        session_id: &str,
        framed_ip: Option<Ipv4Addr>,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        let response =
            self.client
                .accounting_start(username, session_id, framed_ip, calling_station_id)?;

        self.active_sessions.insert(
            session_id.to_string(),
            RadiusSessionState {
                username: username.to_string(),
                session_id: session_id.to_string(),
                framed_ip,
                session_time: 0,
                input_octets: 0,
                output_octets: 0,
                input_packets: 0,
                output_packets: 0,
                acct_started: true,
            },
        );

        Ok(response)
    }

    pub fn stop_accounting(
        &mut self,
        session_id: &str,
        terminate_cause: u32,
        calling_station_id: &str,
    ) -> Result<RadiusPacket> {
        let state = self
            .active_sessions
            .remove(session_id)
            .ok_or_else(|| anyhow::anyhow!("session '{session_id}' not found"))?;

        self.client.accounting_stop(
            &state.username,
            &state.session_id,
            state.input_octets,
            state.output_octets,
            state.session_time,
            state.input_packets,
            state.output_packets,
            terminate_cause,
            state.framed_ip,
            calling_station_id,
        )
    }

    pub fn update_stats(
        &mut self,
        session_id: &str,
        input_octets: u64,
        output_octets: u64,
        session_time: u32,
        input_packets: u64,
        output_packets: u64,
    ) -> Result<()> {
        let state = self
            .active_sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("session '{session_id}' not found"))?;

        state.input_octets = input_octets;
        state.output_octets = output_octets;
        state.session_time = session_time;
        state.input_packets = input_packets;
        state.output_packets = output_packets;
        Ok(())
    }
}

pub const VENDOR_MIKROTIK: u32 = 14988;
pub const ATTR_MIKROTIK_RATE_LIMIT: u8 = 8;
pub const ATTR_VENDOR_SPECIFIC: u8 = 26;
pub const ATTR_WISPR_BANDWIDTH_MAX_UP: u8 = 102;
pub const ATTR_WISPR_BANDWIDTH_MAX_DOWN: u8 = 103;

#[derive(Debug, Clone, PartialEq)]
pub struct BandwidthLimit {
    pub upload_rate: u64,
    pub download_rate: u64,
    pub upload_burst: Option<u64>,
    pub download_burst: Option<u64>,
    pub priority: u8,
}

pub fn parse_mikrotik_rate_limit(raw: &str) -> Option<BandwidthLimit> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let rates: Vec<&str> = parts[0].split('/').collect();
    let upload_rate = rates.first().and_then(|s| parse_bandwidth_value(s))?;
    let download_rate = rates.get(1).and_then(|s| parse_bandwidth_value(s))?;

    let mut upload_burst: Option<u64> = None;
    let mut download_burst: Option<u64> = None;
    let mut priority: u8 = 8;

    if parts.len() >= 2 {
        let bursts: Vec<&str> = parts[1].split('/').collect();
        upload_burst = bursts.first().and_then(|s| parse_bandwidth_value(s));
        download_burst = bursts.get(1).and_then(|s| parse_bandwidth_value(s));
    }

    if parts.len() >= 3 {
        priority = parts[2].parse().unwrap_or(8);
    }

    if upload_rate == 0 && download_rate == 0 {
        return None;
    }

    Some(BandwidthLimit {
        upload_rate,
        download_rate,
        upload_burst,
        download_burst,
        priority: priority.min(7),
    })
}

fn parse_bandwidth_value(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if s.is_empty() || s == "0" {
        return Some(0);
    }
    if let Ok(val) = s.parse::<u64>() {
        return Some(val);
    }
    if let Some(rest) = s.strip_suffix('k') {
        return rest.parse::<u64>().ok();
    }
    if let Some(rest) = s.strip_suffix('m') {
        return rest.parse::<u64>().ok().map(|v| v * 1000);
    }
    if let Some(rest) = s.strip_suffix('g') {
        return rest.parse::<u64>().ok().map(|v| v * 1000 * 1000);
    }
    None
}

pub fn parse_bandwidth_from_response(
    packet: &RadiusPacket,
) -> Vec<crate::user::types::BandwidthProfile> {
    let mut profiles = Vec::new();

    for attr in &packet.attributes {
        if attr.attr_type == ATTR_FILTER_ID
            && let Ok(s) = String::from_utf8(attr.value.clone())
        {
            let parts: Vec<&str> = s.splitn(2, ':').collect();
            if parts.len() == 2
                && parts[0].eq_ignore_ascii_case("rate-limit")
                && let Some(limit) = parse_mikrotik_rate_limit(parts[1])
            {
                profiles.push(crate::user::types::BandwidthProfile {
                    name: format!("radius-rate-limit-{}", profiles.len()),
                    upload_rate: limit.upload_rate,
                    download_rate: limit.download_rate,
                    upload_burst: limit.upload_burst,
                    download_burst: limit.download_burst,
                    priority: limit.priority,
                });
            }
        }
    }

    let max_up = packet.find_attr_u32(ATTR_WISPR_BANDWIDTH_MAX_UP);
    let max_down = packet.find_attr_u32(ATTR_WISPR_BANDWIDTH_MAX_DOWN);
    if let (Some(up), Some(down)) = (max_up, max_down) {
        profiles.push(crate::user::types::BandwidthProfile {
            name: "radius-wispr".into(),
            upload_rate: up as u64,
            download_rate: down as u64,
            upload_burst: None,
            download_burst: None,
            priority: 3,
        });
    }

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radius_attribute_encode_decode() {
        let attr = RadiusAttribute::new_string(ATTR_USER_NAME, "testuser");
        let encoded = attr.encode();
        let (decoded, consumed) = RadiusAttribute::decode(&encoded).unwrap();
        assert_eq!(decoded.attr_type, ATTR_USER_NAME);
        assert_eq!(decoded.as_string().unwrap(), "testuser");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_radius_attribute_u32() {
        let attr = RadiusAttribute::new_u32(ATTR_SERVICE_TYPE, SERVICE_FRAMED);
        let encoded = attr.encode();
        let (decoded, _) = RadiusAttribute::decode(&encoded).unwrap();
        assert_eq!(decoded.as_u32().unwrap(), SERVICE_FRAMED);
    }

    #[test]
    fn test_radius_attribute_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let attr = RadiusAttribute::new_ip(ATTR_FRAMED_IP_ADDRESS, ip);
        let encoded = attr.encode();
        let (decoded, _) = RadiusAttribute::decode(&encoded).unwrap();
        assert_eq!(decoded.as_ip().unwrap(), ip);
    }

    #[test]
    fn test_radius_packet_encode_decode_access_request() {
        let mut pkt = RadiusPacket::new(ACCESS_REQUEST, 42);
        pkt.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_NAME, "user1"));
        pkt.attributes
            .push(RadiusAttribute::new_string(ATTR_USER_PASSWORD, "pass1"));
        pkt.attributes.push(RadiusAttribute::new_ip(
            ATTR_NAS_IP_ADDRESS,
            Ipv4Addr::new(10, 0, 0, 1),
        ));

        let encoded = pkt.encode();
        let decoded = RadiusPacket::decode(&encoded).unwrap();

        assert_eq!(decoded.code, ACCESS_REQUEST);
        assert_eq!(decoded.identifier, 42);
        assert_eq!(decoded.find_attr_string(ATTR_USER_NAME).unwrap(), "user1");
        assert_eq!(
            decoded.find_attr_string(ATTR_USER_PASSWORD).unwrap(),
            "pass1"
        );
    }

    #[test]
    fn test_radius_auth_accept() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        backend.add_user(UserRecord::new("user1", "pass1", true));

        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let response = client
            .authenticate("user1", "pass1", "aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert_eq!(response.code, ACCESS_ACCEPT);
        assert_eq!(
            response.find_attr_u32(ATTR_SERVICE_TYPE).unwrap(),
            SERVICE_FRAMED
        );
    }

    #[test]
    fn test_radius_auth_reject() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        backend.add_user(UserRecord::new("user1", "pass1", false));

        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let response = client
            .authenticate("user1", "pass1", "aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert_eq!(response.code, ACCESS_REJECT);
    }

    #[test]
    fn test_radius_auth_user_not_found() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let result = client.authenticate("unknown", "pass", "aa:bb:cc:dd:ee:ff");
        assert!(result.is_err());
    }

    #[test]
    fn test_radius_auth_with_ip_assignment() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        let mut record = UserRecord::new("user1", "pass1", true);
        record.ip_address = Some(Ipv4Addr::new(10, 0, 1, 100));
        backend.add_user(record);

        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let response = client
            .authenticate("user1", "pass1", "aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert_eq!(response.code, ACCESS_ACCEPT);
        let framed_ip = response.find_attr_ip(ATTR_FRAMED_IP_ADDRESS).unwrap();
        assert_eq!(framed_ip, Ipv4Addr::new(10, 0, 1, 100));
    }

    #[test]
    fn test_accounting_start_stop() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        backend.add_user(UserRecord::new("user1", "pass1", true));

        let client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let mut mgr = RadiusSessionManager::new(client);

        // Accounting Start
        let resp = mgr
            .start_accounting(
                "user1",
                "session-001",
                Some(Ipv4Addr::new(10, 0, 1, 100)),
                "aa:bb:cc:dd:ee:ff",
            )
            .unwrap();
        assert_eq!(resp.code, ACCOUNTING_RESPONSE);
        assert_eq!(mgr.active_sessions().len(), 1);

        // Update stats
        mgr.update_stats("session-001", 1000000, 5000000, 3600, 10000, 20000)
            .unwrap();

        // Accounting Stop
        let resp = mgr
            .stop_accounting("session-001", TERMINATE_USER_REQUEST, "aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert_eq!(resp.code, ACCOUNTING_RESPONSE);
        assert_eq!(mgr.active_sessions().len(), 0);
    }

    #[test]
    fn test_accounting_interim() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        backend.add_user(UserRecord::new("user1", "pass1", true));

        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let resp = client
            .accounting_interim(
                "user1",
                "session-001",
                5000000,
                25000000,
                1800,
                Some(Ipv4Addr::new(10, 0, 1, 100)),
            )
            .unwrap();

        assert_eq!(resp.code, ACCOUNTING_RESPONSE);
    }

    #[test]
    fn test_radius_packet_decode_truncated() {
        let result = RadiusPacket::decode(&[ACCESS_REQUEST, 1, 0, 20, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_not_found_stop() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        let client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");
        let mut mgr = RadiusSessionManager::new(client);

        let result =
            mgr.stop_accounting("nonexistent", TERMINATE_USER_REQUEST, "aa:bb:cc:dd:ee:ff");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_users_auth() {
        let backend = MockRadiusBackend::new("secret", "nas01");
        backend.add_user(UserRecord::new("user1", "pass1", true));
        backend.add_user(UserRecord::new("user2", "pass2", true));
        backend.add_user(UserRecord::new("user3", "pass3", false));
        assert_eq!(backend.user_count(), 3);

        let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "secret", "nas01");

        let r1 = client.authenticate("user1", "pass1", "mac1").unwrap();
        assert_eq!(r1.code, ACCESS_ACCEPT);

        let r2 = client.authenticate("user2", "pass2", "mac2").unwrap();
        assert_eq!(r2.code, ACCESS_ACCEPT);

        let r3 = client.authenticate("user3", "pass3", "mac3").unwrap();
        assert_eq!(r3.code, ACCESS_REJECT);
    }

    #[test]
    fn test_radius_attribute_too_short() {
        let result = RadiusAttribute::decode(&[ATTR_USER_NAME]);
        assert!(result.is_err());
    }

    #[test]
    fn test_radius_custom_attributes() {
        let attr = RadiusAttribute::new_bytes(ATTR_FILTER_ID, vec![0x01, 0x02, 0x03]);
        let encoded = attr.encode();
        let (decoded, _) = RadiusAttribute::decode(&encoded).unwrap();
        assert_eq!(decoded.attr_type, ATTR_FILTER_ID);
        assert_eq!(decoded.value, vec![0x01, 0x02, 0x03]);
    }

    // ─── Bandwidth Parsing Tests ──────────────────────

    #[test]
    fn test_parse_mikrotik_rate_limit_simple() {
        let limit = parse_mikrotik_rate_limit("10M/10M").unwrap();
        assert_eq!(limit.upload_rate, 10000);
        assert_eq!(limit.download_rate, 10000);
        assert_eq!(limit.priority, 7);
    }

    #[test]
    fn test_parse_mikrotik_rate_limit_with_burst() {
        let limit = parse_mikrotik_rate_limit("50M/100M 5M/10M").unwrap();
        assert_eq!(limit.upload_rate, 50000);
        assert_eq!(limit.download_rate, 100000);
        assert_eq!(limit.upload_burst.unwrap(), 5000);
        assert_eq!(limit.download_burst.unwrap(), 10000);
    }

    #[test]
    fn test_parse_mikrotik_rate_limit_with_priority() {
        let limit = parse_mikrotik_rate_limit("20M/20M 2M/2M 3").unwrap();
        assert_eq!(limit.upload_rate, 20000);
        assert_eq!(limit.priority, 3);
    }

    #[test]
    fn test_parse_mikrotik_rate_limit_zero() {
        let result = parse_mikrotik_rate_limit("0/0");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_mikrotik_rate_limit_kbps() {
        let limit = parse_mikrotik_rate_limit("512k/1M").unwrap();
        assert_eq!(limit.upload_rate, 512);
        assert_eq!(limit.download_rate, 1000);
    }

    #[test]
    fn test_parse_bandwidth_value_raw() {
        assert_eq!(parse_bandwidth_value("10000").unwrap(), 10000);
        assert_eq!(parse_bandwidth_value("0").unwrap(), 0);
    }

    #[test]
    fn test_parse_bandwidth_value_suffixes() {
        assert_eq!(parse_bandwidth_value("100k").unwrap(), 100);
        assert_eq!(parse_bandwidth_value("10m").unwrap(), 10000);
        assert_eq!(parse_bandwidth_value("1g").unwrap(), 1000000);
    }

    #[test]
    fn test_parse_bandwidth_from_wispr_attributes() {
        let mut pkt = RadiusPacket::new(ACCESS_ACCEPT, 1);
        pkt.attributes
            .push(RadiusAttribute::new_u32(ATTR_WISPR_BANDWIDTH_MAX_UP, 50000));
        pkt.attributes.push(RadiusAttribute::new_u32(
            ATTR_WISPR_BANDWIDTH_MAX_DOWN,
            100000,
        ));

        let profiles = parse_bandwidth_from_response(&pkt);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].upload_rate, 50000);
        assert_eq!(profiles[0].download_rate, 100000);
        assert_eq!(profiles[0].name, "radius-wispr");
    }

    #[test]
    fn test_parse_bandwidth_from_filter_id() {
        let mut pkt = RadiusPacket::new(ACCESS_ACCEPT, 1);
        let val = "rate-limit:50M/100M 5M/10M 3";
        pkt.attributes
            .push(RadiusAttribute::new_string(ATTR_FILTER_ID, val));

        let profiles = parse_bandwidth_from_response(&pkt);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].upload_rate, 50000);
        assert_eq!(profiles[0].download_rate, 100000);
        assert_eq!(profiles[0].priority, 3);
    }

    #[test]
    fn test_parse_bandwidth_no_attributes() {
        let pkt = RadiusPacket::new(ACCESS_ACCEPT, 1);
        let profiles = parse_bandwidth_from_response(&pkt);
        assert!(profiles.is_empty());
    }
}
