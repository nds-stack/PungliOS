use anyhow::{Result, bail};

use super::types::*;

pub const PPP_LCP: u16 = 0xc021;
pub const PPP_PAP: u16 = 0xc023;
pub const PPP_CHAP: u16 = 0xc223;
pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV6CP: u16 = 0x8057;

pub const LCP_CONFIGURE_REQUEST: u8 = 1;
pub const LCP_CONFIGURE_ACK: u8 = 2;
pub const LCP_CONFIGURE_NAK: u8 = 3;
pub const LCP_CONFIGURE_REJECT: u8 = 4;
pub const LCP_TERMINATE_REQUEST: u8 = 5;
pub const LCP_TERMINATE_ACK: u8 = 6;
pub const LCP_CODE_REJECT: u8 = 7;
pub const LCP_PROTOCOL_REJECT: u8 = 8;
pub const LCP_ECHO_REQUEST: u8 = 9;
pub const LCP_ECHO_REPLY: u8 = 10;

pub const LCP_OPT_MRU: u8 = 1;
pub const LCP_OPT_ACCM: u8 = 2;
pub const LCP_OPT_AUTH_PROTO: u8 = 3;
pub const LCP_OPT_MAGIC_NUMBER: u8 = 5;
pub const LCP_OPT_PFC: u8 = 7;
pub const LCP_OPT_ACFC: u8 = 8;

pub const IPCP_CONFIGURE_REQUEST: u8 = 1;
pub const IPCP_CONFIGURE_ACK: u8 = 2;
pub const IPCP_CONFIGURE_NAK: u8 = 3;
pub const IPCP_CONFIGURE_REJECT: u8 = 4;

pub const IPCP_OPT_IP_ADDRESS: u8 = 3;
pub const IPCP_OPT_PRIMARY_DNS: u8 = 129;
pub const IPCP_OPT_SECONDARY_DNS: u8 = 131;

pub const PAP_AUTH_REQUEST: u8 = 1;
pub const PAP_AUTH_ACK: u8 = 2;
pub const PAP_AUTH_NAK: u8 = 3;

pub const CHAP_CHALLENGE: u8 = 1;
pub const CHAP_RESPONSE: u8 = 2;
pub const CHAP_SUCCESS: u8 = 3;
pub const CHAP_FAILURE: u8 = 4;

#[derive(Debug, Clone, PartialEq)]
pub struct LcpOption {
    pub opt_type: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PppFrame {
    pub protocol: u16,
    pub code: u8,
    pub identifier: u8,
    pub data: Vec<u8>,
    pub auth_payload: Option<Vec<u8>>,
    pub options: Vec<LcpOption>,
}

impl PppFrame {
    pub fn new(protocol: u16, code: u8, identifier: u8) -> Self {
        Self {
            protocol,
            code,
            identifier,
            data: vec![],
            auth_payload: None,
            options: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn protocol_name(protocol: u16) -> &'static str {
        match protocol {
            PPP_LCP => "LCP",
            PPP_PAP => "PAP",
            PPP_CHAP => "CHAP",
            PPP_IPCP => "IPCP",
            PPP_IPV6CP => "IPV6CP",
            _ => "UNKNOWN",
        }
    }

    pub fn encoded_len(&self) -> usize {
        let mut len: usize = 2 + 1 + 1 + 2;
        let opts_len: usize = self.options.iter().map(|o| 2 + o.value.len()).sum();
        if let Some(ref payload) = self.auth_payload {
            len += 1 + payload.len();
        } else {
            len += opts_len + self.data.len();
        }
        len
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        buf.extend_from_slice(&self.protocol.to_be_bytes());
        buf.push(self.code);
        buf.push(self.identifier);

        if let Some(ref payload) = self.auth_payload {
            let payload_len = (payload.len() + 1) as u16;
            buf.extend_from_slice(&payload_len.to_be_bytes());
            buf.extend_from_slice(payload);
        } else {
            let opts_len: usize = self.options.iter().map(|o| 2 + o.value.len()).sum();
            let total_len = (opts_len + self.data.len()) as u16;
            buf.extend_from_slice(&total_len.to_be_bytes());
            for opt in &self.options {
                buf.push(opt.opt_type);
                buf.push((opt.value.len() + 2) as u8);
                buf.extend_from_slice(&opt.value);
            }
            buf.extend_from_slice(&self.data);
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 6 {
            bail!("PPP frame too short: {} bytes", data.len());
        }
        let protocol = u16::from_be_bytes([data[0], data[1]]);
        let code = data[2];
        let identifier = data[3];
        let length = u16::from_be_bytes([data[4], data[5]]) as usize;

        let payload_start = 6;
        let payload = &data[payload_start..];
        let payload_end = std::cmp::min(payload.len(), length);

        let mut options = Vec::new();
        let mut raw_data = Vec::new();
        let mut auth_payload: Option<Vec<u8>> = None;

        match protocol {
            PPP_PAP => {
                if payload_end >= 1 {
                    let peer_id_len = payload[0] as usize;
                    let peer_id = payload[1..1 + peer_id_len].to_vec();
                    let passwd_len = payload[1 + peer_id_len] as usize;
                    let passwd = payload[2 + peer_id_len..2 + peer_id_len + passwd_len].to_vec();
                    let mut combined = vec![peer_id_len as u8];
                    combined.extend_from_slice(&peer_id);
                    combined.push(passwd_len as u8);
                    combined.extend_from_slice(&passwd);
                    auth_payload = Some(combined);
                }
            }
            PPP_CHAP => {
                if payload_end >= 1 {
                    auth_payload = Some(payload[0..payload_end].to_vec());
                }
            }
            _ => {
                let mut offset = 0;
                while offset + 2 <= payload_end {
                    let opt_type = payload[offset];
                    let opt_len = payload[offset + 1] as usize;
                    if opt_len < 2 || offset + 2 + opt_len > payload_end + 2 {
                        break;
                    }
                    let value_len = opt_len.saturating_sub(2);
                    let value = payload[offset + 2..offset + 2 + value_len].to_vec();
                    options.push(LcpOption { opt_type, value });
                    offset += 2 + value_len;
                }
                if offset < payload_end {
                    raw_data = payload[offset..payload_end].to_vec();
                }
            }
        }

        Ok(Self {
            protocol,
            code,
            identifier,
            data: raw_data,
            auth_payload,
            options,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PppState {
    Initial,
    Starting,
    Closed,
    Stopped,
    Closing,
    Stopping,
    RequestSent,
    AckReceived,
    AckSent,
    Opened,
}

impl PppState {
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Opened)
    }
}

#[derive(Debug, Clone)]
pub struct PppNegotiation<Backend: crate::pppoe::discovery::PppoeBackend> {
    #[allow(dead_code)]
    backend: Option<Backend>,
    lcp_state: PppState,
    ipcp_state: PppState,
    auth_state: AuthState,
    next_id: u8,
    lcp_opts: LcpConfig,
    ipcp_opts: IpcpConfig,
    #[allow(dead_code)]
    remote_lcp_opts: LcpConfig,
    #[allow(dead_code)]
    remote_ipcp_opts: IpcpConfig,
    accepted_auth: Option<AuthProtocol>,
    username: Option<String>,
    password: Option<String>,
    ip_assigned: Option<std::net::Ipv4Addr>,
}

impl<Backend: crate::pppoe::discovery::PppoeBackend> PppNegotiation<Backend> {
    pub fn new_server(
        backend: Backend,
        local_ip: std::net::Ipv4Addr,
        dns: Vec<std::net::Ipv4Addr>,
    ) -> Self {
        Self {
            backend: Some(backend),
            lcp_state: PppState::Initial,
            ipcp_state: PppState::Initial,
            auth_state: AuthState::Idle,
            next_id: 0,
            lcp_opts: LcpConfig {
                mru: 1492,
                auth_protocol: Some(AuthProtocol::Chap),
                magic_number: Some(0xdeadbeef),
            },
            ipcp_opts: IpcpConfig {
                ip_address: Some(local_ip),
                dns_servers: dns,
            },
            remote_lcp_opts: LcpConfig::default(),
            remote_ipcp_opts: IpcpConfig::default(),
            accepted_auth: None,
            username: None,
            password: None,
            ip_assigned: None,
        }
    }

    pub fn new_client(
        backend: Backend,
        username: &str,
        password: &str,
        auth: AuthProtocol,
    ) -> Self {
        Self {
            backend: Some(backend),
            lcp_state: PppState::Initial,
            ipcp_state: PppState::Initial,
            auth_state: AuthState::Idle,
            next_id: 0,
            lcp_opts: LcpConfig {
                mru: 1492,
                auth_protocol: None,
                magic_number: Some(0xcafebabe),
            },
            ipcp_opts: IpcpConfig {
                ip_address: None,
                dns_servers: vec![],
            },
            remote_lcp_opts: LcpConfig::default(),
            remote_ipcp_opts: IpcpConfig::default(),
            accepted_auth: Some(auth),
            username: Some(username.into()),
            password: Some(password.into()),
            ip_assigned: None,
        }
    }

    pub fn lcp_state(&self) -> &PppState {
        &self.lcp_state
    }

    pub fn ipcp_state(&self) -> &PppState {
        &self.ipcp_state
    }

    pub fn auth_state(&self) -> &AuthState {
        &self.auth_state
    }

    pub fn assigned_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.ip_assigned
    }

    pub fn is_open(&self) -> bool {
        self.lcp_state.is_open() && self.ipcp_state.is_open()
    }

    fn next_identifier(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    pub fn start_lcp(&mut self) -> PppFrame {
        self.lcp_state = PppState::Starting;
        self.build_lcp_configure_request()
    }

    pub fn process_frame(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        match frame.protocol {
            PPP_LCP => self.process_lcp(frame),
            PPP_PAP => self.process_pap(frame),
            PPP_CHAP => self.process_chap(frame),
            PPP_IPCP => self.process_ipcp(frame),
            _ => {
                let mut reject =
                    PppFrame::new(PPP_LCP, LCP_PROTOCOL_REJECT, self.next_identifier());
                let mut proto_buf = frame.protocol.to_be_bytes().to_vec();
                reject.data.append(&mut proto_buf);
                Ok(Some(reject))
            }
        }
    }

    fn process_lcp(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        match frame.code {
            LCP_CONFIGURE_REQUEST => {
                let response = self.handle_lcp_configure_request(frame);
                match &response {
                    Some(f) if f.code == LCP_CONFIGURE_ACK => {
                        self.lcp_state = PppState::AckSent;
                    }
                    _ => {}
                }
                Ok(response)
            }
            LCP_CONFIGURE_ACK => {
                self.lcp_state = PppState::Opened;
                if let Some(auth) = self.lcp_opts.auth_protocol {
                    self.accepted_auth = Some(auth);
                }
                Ok(None)
            }
            LCP_CONFIGURE_NAK | LCP_CONFIGURE_REJECT => {
                let mut new_opts = LcpConfig::default();
                for opt in &frame.options {
                    match opt.opt_type {
                        LCP_OPT_MRU if opt.value.len() >= 2 => {
                            new_opts.mru = u16::from_be_bytes([opt.value[0], opt.value[1]]);
                        }
                        LCP_OPT_AUTH_PROTO if opt.value.len() >= 2 => {
                            let proto = u16::from_be_bytes([opt.value[0], opt.value[1]]);
                            new_opts.auth_protocol = match proto {
                                PPP_PAP => Some(AuthProtocol::Pap),
                                PPP_CHAP => Some(AuthProtocol::Chap),
                                _ => None,
                            };
                        }
                        LCP_OPT_MAGIC_NUMBER if opt.value.len() >= 4 => {
                            new_opts.magic_number = Some(u32::from_be_bytes([
                                opt.value[0],
                                opt.value[1],
                                opt.value[2],
                                opt.value[3],
                            ]));
                        }
                        _ => {}
                    }
                }
                self.lcp_opts = new_opts;
                self.lcp_state = PppState::RequestSent;
                Ok(Some(self.build_lcp_configure_request()))
            }
            LCP_TERMINATE_REQUEST => {
                self.lcp_state = PppState::Stopping;
                let mut ack = PppFrame::new(PPP_LCP, LCP_TERMINATE_ACK, frame.identifier);
                ack.data = frame.data.clone();
                Ok(Some(ack))
            }
            LCP_TERMINATE_ACK => {
                self.lcp_state = PppState::Closed;
                Ok(None)
            }
            LCP_ECHO_REQUEST => {
                let mut reply = PppFrame::new(PPP_LCP, LCP_ECHO_REPLY, frame.identifier);
                reply.data.extend_from_slice(&[0; 4]);
                if let Some(magic) = self.lcp_opts.magic_number {
                    reply.data.extend_from_slice(&magic.to_be_bytes());
                }
                Ok(Some(reply))
            }
            LCP_ECHO_REPLY => Ok(None),
            _ => {
                let mut reject = PppFrame::new(PPP_LCP, LCP_CODE_REJECT, self.next_identifier());
                reject.data.push(frame.code);
                Ok(Some(reject))
            }
        }
    }

    fn handle_lcp_configure_request(&self, frame: &PppFrame) -> Option<PppFrame> {
        let mut nak_options: Vec<LcpOption> = Vec::new();
        let mut reject_options: Vec<LcpOption> = Vec::new();
        let mut accepted: Vec<LcpOption> = Vec::new();

        for opt in &frame.options {
            match opt.opt_type {
                LCP_OPT_MRU => {
                    if opt.value.len() >= 2 {
                        let mru = u16::from_be_bytes([opt.value[0], opt.value[1]]);
                        if mru >= 128 && mru <= self.lcp_opts.mru {
                            accepted.push(opt.clone());
                        } else {
                            nak_options.push(LcpOption {
                                opt_type: LCP_OPT_MRU,
                                value: self.lcp_opts.mru.to_be_bytes().to_vec(),
                            });
                        }
                    }
                }
                LCP_OPT_AUTH_PROTO => {
                    if let Some(_expected) = self.lcp_opts.auth_protocol {
                        accepted.push(opt.clone());
                    } else {
                        reject_options.push(opt.clone());
                    }
                }
                LCP_OPT_MAGIC_NUMBER => {
                    accepted.push(opt.clone());
                }
                LCP_OPT_ACCM => {
                    accepted.push(opt.clone());
                }
                _ => {
                    reject_options.push(opt.clone());
                }
            }
        }

        if !reject_options.is_empty() {
            let mut nak = PppFrame::new(PPP_LCP, LCP_CONFIGURE_REJECT, frame.identifier);
            nak.options = reject_options;
            return Some(nak);
        }

        if !nak_options.is_empty() {
            let mut nak = PppFrame::new(PPP_LCP, LCP_CONFIGURE_NAK, frame.identifier);
            nak.options = nak_options;
            return Some(nak);
        }

        let mut ack = PppFrame::new(PPP_LCP, LCP_CONFIGURE_ACK, frame.identifier);
        ack.options = accepted;
        Some(ack)
    }

    fn build_lcp_configure_request(&mut self) -> PppFrame {
        let mut req = PppFrame::new(PPP_LCP, LCP_CONFIGURE_REQUEST, self.next_identifier());
        req.options.push(LcpOption {
            opt_type: LCP_OPT_MRU,
            value: self.lcp_opts.mru.to_be_bytes().to_vec(),
        });
        req.options.push(LcpOption {
            opt_type: LCP_OPT_ACCM,
            value: vec![0x00, 0x00, 0x00, 0x00],
        });
        if let Some(auth) = self.lcp_opts.auth_protocol {
            let proto = match auth {
                AuthProtocol::Pap => PPP_PAP,
                AuthProtocol::Chap => PPP_CHAP,
                AuthProtocol::MsChapV2 => PPP_CHAP,
            };
            let mut val = proto.to_be_bytes().to_vec();
            match auth {
                AuthProtocol::Chap => val.push(5),
                AuthProtocol::MsChapV2 => val.push(0x81),
                _ => {}
            }
            req.options.push(LcpOption {
                opt_type: LCP_OPT_AUTH_PROTO,
                value: val,
            });
        }
        if let Some(magic) = self.lcp_opts.magic_number {
            req.options.push(LcpOption {
                opt_type: LCP_OPT_MAGIC_NUMBER,
                value: magic.to_be_bytes().to_vec(),
            });
        }
        req
    }

    fn process_pap(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        match frame.code {
            PAP_AUTH_REQUEST => {
                if let Some(ref payload) = frame.auth_payload
                    && payload.len() > 2
                {
                    let user_len = payload[0] as usize;
                    let user = String::from_utf8_lossy(&payload[1..1 + user_len]).to_string();
                    let pass_len = if 2 + user_len <= payload.len() {
                        payload[1 + user_len] as usize
                    } else {
                        0
                    };
                    let start = 2 + user_len;
                    let pass = if start + pass_len <= payload.len() {
                        String::from_utf8_lossy(&payload[start..start + pass_len]).to_string()
                    } else {
                        String::new()
                    };

                    let valid_user = self.username.as_deref() == Some(user.as_str());
                    let valid_pass = self.password.as_deref() == Some(pass.as_str());

                    if valid_user && valid_pass {
                        self.auth_state = AuthState::Authenticated;
                        return Ok(Some(PppFrame::new(PPP_PAP, PAP_AUTH_ACK, frame.identifier)));
                    }
                }
                Ok(Some(PppFrame::new(PPP_PAP, PAP_AUTH_NAK, frame.identifier)))
            }
            PAP_AUTH_ACK => {
                self.auth_state = AuthState::Authenticated;
                Ok(None)
            }
            PAP_AUTH_NAK => {
                self.auth_state = AuthState::Failed;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn process_chap(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        match frame.code {
            CHAP_CHALLENGE => {
                self.auth_state = AuthState::AwaitingAuth;
                Ok(None)
            }
            CHAP_RESPONSE => {
                self.auth_state = AuthState::Authenticated;
                Ok(Some(PppFrame::new(
                    PPP_CHAP,
                    CHAP_SUCCESS,
                    frame.identifier,
                )))
            }
            CHAP_SUCCESS => {
                self.auth_state = AuthState::Authenticated;
                Ok(None)
            }
            CHAP_FAILURE => {
                self.auth_state = AuthState::Failed;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub fn start_auth(&mut self) -> Option<PppFrame> {
        match self.accepted_auth {
            Some(AuthProtocol::Pap) => {
                let mut req = PppFrame::new(PPP_PAP, PAP_AUTH_REQUEST, self.next_identifier());
                let user = self.username.as_deref().unwrap_or("");
                let pass = self.password.as_deref().unwrap_or("");
                let mut payload = vec![user.len() as u8];
                payload.extend_from_slice(user.as_bytes());
                payload.push(pass.len() as u8);
                payload.extend_from_slice(pass.as_bytes());
                req.auth_payload = Some(payload);
                self.auth_state = AuthState::AwaitingAuth;
                Some(req)
            }
            Some(AuthProtocol::Chap) | Some(AuthProtocol::MsChapV2) => {
                let challenge: [u8; 16] = [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10,
                ];
                let mut req = PppFrame::new(PPP_CHAP, CHAP_CHALLENGE, self.next_identifier());
                let mut payload = vec![16];
                payload.extend_from_slice(&challenge);
                let user = self.username.as_deref().unwrap_or("");
                payload.extend_from_slice(user.as_bytes());
                req.auth_payload = Some(payload);
                self.auth_state = AuthState::AwaitingAuth;
                Some(req)
            }
            None => None,
        }
    }

    fn process_ipcp(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        match frame.code {
            IPCP_CONFIGURE_REQUEST => {
                let response = self.handle_ipcp_configure_request(frame);
                Ok(response)
            }
            IPCP_CONFIGURE_ACK => {
                self.ipcp_state = PppState::Opened;
                Ok(None)
            }
            IPCP_CONFIGURE_NAK | IPCP_CONFIGURE_REJECT => {
                let mut new_opts = IpcpConfig::default();
                for opt in &frame.options {
                    if opt.opt_type == IPCP_OPT_IP_ADDRESS && opt.value.len() >= 4 {
                        new_opts.ip_address = Some(std::net::Ipv4Addr::new(
                            opt.value[0],
                            opt.value[1],
                            opt.value[2],
                            opt.value[3],
                        ));
                    }
                }
                self.ipcp_opts = new_opts;
                self.ipcp_state = PppState::RequestSent;
                Ok(Some(self.build_ipcp_configure_request()))
            }
            _ => Ok(None),
        }
    }

    fn handle_ipcp_configure_request(&self, frame: &PppFrame) -> Option<PppFrame> {
        let mut nak_options: Vec<LcpOption> = Vec::new();
        let mut accepted: Vec<LcpOption> = Vec::new();

        for opt in &frame.options {
            match opt.opt_type {
                IPCP_OPT_IP_ADDRESS if opt.value.len() >= 4 => {
                    let ip = std::net::Ipv4Addr::new(
                        opt.value[0],
                        opt.value[1],
                        opt.value[2],
                        opt.value[3],
                    );
                    if self.ipcp_opts.ip_address == Some(ip) {
                        accepted.push(opt.clone());
                    } else if let Some(ip_addr) = self.ipcp_opts.ip_address {
                        nak_options.push(LcpOption {
                            opt_type: IPCP_OPT_IP_ADDRESS,
                            value: ip_addr.octets().to_vec(),
                        });
                    } else {
                        nak_options.push(LcpOption {
                            opt_type: IPCP_OPT_IP_ADDRESS,
                            value: [0, 0, 0, 0].to_vec(),
                        });
                    }
                }
                IPCP_OPT_PRIMARY_DNS | IPCP_OPT_SECONDARY_DNS => {
                    if self.ipcp_opts.dns_servers.is_empty() {
                        accepted.push(opt.clone());
                    } else if let Some(dns) = self.ipcp_opts.dns_servers.first() {
                        accepted.push(LcpOption {
                            opt_type: opt.opt_type,
                            value: dns.octets().to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }

        if !nak_options.is_empty() {
            let mut nak = PppFrame::new(PPP_IPCP, IPCP_CONFIGURE_NAK, frame.identifier);
            nak.options = nak_options;
            return Some(nak);
        }

        let mut ack = PppFrame::new(PPP_IPCP, IPCP_CONFIGURE_ACK, frame.identifier);
        ack.options = accepted;
        Some(ack)
    }

    pub fn start_ipcp(&mut self) -> PppFrame {
        self.ipcp_state = PppState::Starting;
        self.build_ipcp_configure_request()
    }

    fn build_ipcp_configure_request(&mut self) -> PppFrame {
        let mut req = PppFrame::new(PPP_IPCP, IPCP_CONFIGURE_REQUEST, self.next_identifier());
        if let Some(ip) = self.ipcp_opts.ip_address {
            req.options.push(LcpOption {
                opt_type: IPCP_OPT_IP_ADDRESS,
                value: ip.octets().to_vec(),
            });
        } else {
            req.options.push(LcpOption {
                opt_type: IPCP_OPT_IP_ADDRESS,
                value: vec![0, 0, 0, 0],
            });
        }
        if !self.ipcp_opts.dns_servers.is_empty() {
            if let Some(dns) = self.ipcp_opts.dns_servers.first() {
                req.options.push(LcpOption {
                    opt_type: IPCP_OPT_PRIMARY_DNS,
                    value: dns.octets().to_vec(),
                });
            }
            if self.ipcp_opts.dns_servers.len() > 1 {
                let dns2 = self.ipcp_opts.dns_servers[1];
                req.options.push(LcpOption {
                    opt_type: IPCP_OPT_SECONDARY_DNS,
                    value: dns2.octets().to_vec(),
                });
            }
        }
        req
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    Idle,
    AwaitingAuth,
    Authenticated,
    Failed,
}

#[derive(Debug, Clone)]
pub struct PppSession<Backend: crate::pppoe::discovery::PppoeBackend> {
    pub session_id: u16,
    pub iface: String,
    pub negotiation: PppNegotiation<Backend>,
    pub client_mac: [u8; 6],
    pub username: Option<String>,
    pub service_name: Option<String>,
    pub ip_address: Option<std::net::Ipv4Addr>,
    active: bool,
    tx_queue: std::collections::VecDeque<PppFrame>,
}

impl<Backend: crate::pppoe::discovery::PppoeBackend> PppSession<Backend> {
    pub fn new_client(
        backend: Backend,
        session_id: u16,
        iface: &str,
        client_mac: [u8; 6],
        username: &str,
        password: &str,
        auth: AuthProtocol,
    ) -> Self {
        Self {
            session_id,
            iface: iface.to_string(),
            negotiation: PppNegotiation::new_client(backend, username, password, auth),
            client_mac,
            username: Some(username.to_string()),
            service_name: None,
            ip_address: None,
            active: false,
            tx_queue: std::collections::VecDeque::new(),
        }
    }

    pub fn new_server(
        backend: Backend,
        session_id: u16,
        iface: &str,
        client_mac: [u8; 6],
        local_ip: std::net::Ipv4Addr,
        dns: Vec<std::net::Ipv4Addr>,
    ) -> Self {
        Self {
            session_id,
            iface: iface.to_string(),
            negotiation: PppNegotiation::new_server(backend, local_ip, dns),
            client_mac,
            username: None,
            service_name: None,
            ip_address: None,
            active: false,
            tx_queue: std::collections::VecDeque::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn is_negotiated(&self) -> bool {
        self.negotiation.is_open() && self.active
    }

    pub fn start(&mut self) -> PppFrame {
        self.active = true;
        self.negotiation.start_lcp()
    }

    pub fn process_frame(&mut self, frame: &PppFrame) -> Result<Option<PppFrame>> {
        self.negotiation.process_frame(frame)
    }

    pub fn queue_frame(&mut self, frame: PppFrame) {
        self.tx_queue.push_back(frame);
    }

    pub fn next_tx_frame(&mut self) -> Option<PppFrame> {
        self.tx_queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pppoe::discovery::MockPppoeBackend;

    #[test]
    fn test_ppp_frame_encode_decode_lcp() {
        let mut frame = PppFrame::new(PPP_LCP, LCP_CONFIGURE_REQUEST, 1);
        frame.options.push(LcpOption {
            opt_type: LCP_OPT_MRU,
            value: 1492u16.to_be_bytes().to_vec(),
        });
        frame.options.push(LcpOption {
            opt_type: LCP_OPT_MAGIC_NUMBER,
            value: 0xcafebabeu32.to_be_bytes().to_vec(),
        });

        let encoded = frame.encode();
        let decoded = PppFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.protocol, PPP_LCP);
        assert_eq!(decoded.code, LCP_CONFIGURE_REQUEST);
        assert_eq!(decoded.identifier, 1);
        assert_eq!(decoded.options.len(), 2);
        assert_eq!(decoded.options[0].opt_type, LCP_OPT_MRU);
        assert_eq!(decoded.options[1].opt_type, LCP_OPT_MAGIC_NUMBER);
    }

    #[test]
    fn test_ppp_frame_encode_decode_pap() {
        let mut frame = PppFrame::new(PPP_PAP, PAP_AUTH_REQUEST, 2);
        let user = b"testuser";
        let pass = b"testpass";
        let mut payload = vec![user.len() as u8];
        payload.extend_from_slice(user);
        payload.push(pass.len() as u8);
        payload.extend_from_slice(pass);
        frame.auth_payload = Some(payload);

        let encoded = frame.encode();
        let decoded = PppFrame::decode(&encoded).unwrap();

        assert_eq!(decoded.protocol, PPP_PAP);
        assert_eq!(decoded.code, PAP_AUTH_REQUEST);
        assert_eq!(decoded.identifier, 2);
        assert!(decoded.auth_payload.is_some());
    }

    #[test]
    fn test_lcp_configure_request_ack_flow() {
        let backend = MockPppoeBackend::new();
        let mut server = PppNegotiation::new_server(
            backend.clone(),
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            vec![std::net::Ipv4Addr::new(8, 8, 8, 8)],
        );

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "pass1", AuthProtocol::Pap);

        // Client sends LCP Configure-Request
        let client_req = client.start_lcp();
        assert_eq!(client_req.code, LCP_CONFIGURE_REQUEST);

        // Server processes it → sends Configure-Ack
        let server_resp = server.process_frame(&client_req).unwrap();
        assert!(server_resp.is_some());
        let server_ack = server_resp.unwrap();
        assert_eq!(server_ack.code, LCP_CONFIGURE_ACK);
        assert_eq!(server.lcp_state(), &PppState::AckSent);

        // Client receives Ack → LCP open
        client.process_frame(&server_ack).unwrap();
        assert_eq!(client.lcp_state(), &PppState::Opened);
    }

    #[test]
    fn test_pap_auth_flow() {
        let backend = MockPppoeBackend::new();
        let mut server = PppNegotiation::new_server(
            backend.clone(),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            vec![],
        );

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "pass1", AuthProtocol::Pap);

        // Complete LCP
        let lcp_req = client.start_lcp();
        let lcp_ack = server.process_frame(&lcp_req).unwrap().unwrap();
        client.process_frame(&lcp_ack).unwrap();
        assert!(client.lcp_state().is_open());

        // Server expects PAP auth
        server.username = Some("user1".into());
        server.password = Some("pass1".into());

        // Client sends PAP request
        let pap = client.start_auth().unwrap();
        assert_eq!(pap.protocol, PPP_PAP);

        // Server accepts
        let pap_resp = server.process_frame(&pap).unwrap().unwrap();
        assert_eq!(pap_resp.code, PAP_AUTH_ACK);
        assert_eq!(server.auth_state(), &AuthState::Authenticated);

        // Client receives ack
        client.process_frame(&pap_resp).unwrap();
        assert_eq!(client.auth_state(), &AuthState::Authenticated);
    }

    #[test]
    fn test_pap_auth_failure() {
        let backend = MockPppoeBackend::new();
        let mut server = PppNegotiation::new_server(
            backend.clone(),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            vec![],
        );

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "wrongpass", AuthProtocol::Pap);

        // Complete LCP
        let lcp_req = client.start_lcp();
        let lcp_ack = server.process_frame(&lcp_req).unwrap().unwrap();
        client.process_frame(&lcp_ack).unwrap();

        // Server expects different password
        server.username = Some("user1".into());
        server.password = Some("correctpass".into());

        // Client sends PAP request
        let pap = client.start_auth().unwrap();

        // Server rejects
        let pap_resp = server.process_frame(&pap).unwrap().unwrap();
        assert_eq!(pap_resp.code, PAP_AUTH_NAK);
    }

    #[test]
    fn test_chap_auth_flow() {
        let backend = MockPppoeBackend::new();
        let mut server = PppNegotiation::new_server(
            backend.clone(),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            vec![],
        );

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "pass1", AuthProtocol::Chap);

        // Complete LCP
        let lcp_req = client.start_lcp();
        let lcp_ack = server.process_frame(&lcp_req).unwrap().unwrap();
        client.process_frame(&lcp_ack).unwrap();

        // Client initiates CHAP
        let chap = client.start_auth().unwrap();
        assert_eq!(chap.protocol, PPP_CHAP);
        assert_eq!(chap.code, CHAP_CHALLENGE);

        // Server processes challenge
        let _ = server.process_frame(&chap).unwrap();

        // Mock response from server
        let resp = PppFrame::new(PPP_CHAP, CHAP_RESPONSE, chap.identifier);
        server.auth_state = AuthState::Authenticated;
        let server_ack = server.process_frame(&resp).unwrap().unwrap();
        assert_eq!(server_ack.code, CHAP_SUCCESS);

        // Client receives success
        client.process_frame(&server_ack).unwrap();
        assert_eq!(client.auth_state(), &AuthState::Authenticated);
    }

    #[test]
    fn test_ipcp_negotiation() {
        let backend = MockPppoeBackend::new();
        let server_ip = std::net::Ipv4Addr::new(10, 0, 1, 1);
        let client_ip = std::net::Ipv4Addr::new(10, 0, 1, 100);

        let mut server = PppNegotiation::new_server(
            backend.clone(),
            server_ip,
            vec![std::net::Ipv4Addr::new(8, 8, 8, 8)],
        );
        server.ipcp_opts.ip_address = Some(client_ip);

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "pass1", AuthProtocol::Chap);

        // Client sends IPCP Configure-Request
        let client_req = client.start_ipcp();
        assert_eq!(client_req.protocol, PPP_IPCP);

        // Server responds with NAK (suggests different IP)
        let server_resp = server.process_frame(&client_req).unwrap();
        assert!(server_resp.is_some());
        let server_nak = server_resp.unwrap();
        assert_eq!(server_nak.code, IPCP_CONFIGURE_NAK);

        // Client accepts suggested IP and resends
        client.process_frame(&server_nak).unwrap();
        let client_req2 = client.build_ipcp_configure_request();

        // Server acks
        let server_resp2 = server.process_frame(&client_req2).unwrap();
        assert!(server_resp2.is_some());
        let server_ack = server_resp2.unwrap();
        assert_eq!(server_ack.code, IPCP_CONFIGURE_ACK);

        // Client receives ack → IPCP open
        client.process_frame(&server_ack).unwrap();
        assert!(client.ipcp_state().is_open());
    }

    #[test]
    fn test_full_ppp_negotiation_flow() {
        let backend = MockPppoeBackend::new();

        let mut client =
            PppNegotiation::new_client(backend.clone(), "user1", "pass1", AuthProtocol::Pap);

        let mut server = PppNegotiation::new_server(
            backend.clone(),
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            vec![std::net::Ipv4Addr::new(8, 8, 8, 8)],
        );
        server.username = Some("user1".into());
        server.password = Some("pass1".into());
        server.ipcp_opts.ip_address = Some(std::net::Ipv4Addr::new(192, 168, 1, 100));

        // LCP
        let lcp_req = client.start_lcp();
        let lcp_ack = server.process_frame(&lcp_req).unwrap().unwrap();
        client.process_frame(&lcp_ack).unwrap();
        assert!(client.lcp_state().is_open());

        // PAP Auth
        let pap = client.start_auth().unwrap();
        let pap_ack = server.process_frame(&pap).unwrap().unwrap();
        client.process_frame(&pap_ack).unwrap();
        assert_eq!(client.auth_state(), &AuthState::Authenticated);

        // IPCP
        let ipcp_req = client.start_ipcp();
        let ipcp_nak = server.process_frame(&ipcp_req).unwrap().unwrap();
        client.process_frame(&ipcp_nak).unwrap();
        let ipcp_req2 = client.build_ipcp_configure_request();
        let ipcp_ack = server.process_frame(&ipcp_req2).unwrap().unwrap();
        client.process_frame(&ipcp_ack).unwrap();
        assert!(client.ipcp_state().is_open());

        assert!(client.is_open());
    }

    #[test]
    fn test_lcp_echo_request_reply() {
        let backend = MockPppoeBackend::new();
        let mut client =
            PppNegotiation::new_client(backend.clone(), "user", "pass", AuthProtocol::Pap);

        let echo = PppFrame::new(PPP_LCP, LCP_ECHO_REQUEST, 42);
        let reply = client.process_frame(&echo).unwrap();

        assert!(reply.is_some());
        let reply = reply.unwrap();
        assert_eq!(reply.code, LCP_ECHO_REPLY);
        assert_eq!(reply.identifier, 42);
    }

    #[test]
    fn test_lcp_terminate() {
        let backend = MockPppoeBackend::new();
        let mut client =
            PppNegotiation::new_client(backend.clone(), "user", "pass", AuthProtocol::Pap);

        // Set LCP to Opened first
        client.lcp_state = PppState::Opened;

        let terminate = PppFrame::new(PPP_LCP, LCP_TERMINATE_REQUEST, 99);
        let reply = client.process_frame(&terminate).unwrap();

        assert!(reply.is_some());
        let reply = reply.unwrap();
        assert_eq!(reply.code, LCP_TERMINATE_ACK);
        assert_eq!(client.lcp_state(), &PppState::Stopping);

        // Process Terminate-Ack
        let term_ack = PppFrame::new(PPP_LCP, LCP_TERMINATE_ACK, 99);
        client.process_frame(&term_ack).unwrap();
        assert_eq!(client.lcp_state(), &PppState::Closed);
    }

    #[test]
    fn test_ppp_session_lifecycle() {
        let backend = MockPppoeBackend::new();
        let mut session = PppSession::new_client(
            backend,
            1,
            "eth0",
            [0xaa; 6],
            "user1",
            "pass1",
            AuthProtocol::Pap,
        );

        assert!(!session.is_active());
        assert!(!session.is_negotiated());

        let lcp_req = session.start();
        assert!(session.is_active());
        assert_eq!(lcp_req.protocol, PPP_LCP);
    }
}
