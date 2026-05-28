use anyhow::{Result, bail};

pub const DNS_PORT: u16 = 53;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_MX: u16 = 15;
pub const TYPE_NS: u16 = 2;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SOA: u16 = 6;

pub const CLASS_IN: u16 = 1;

pub const OPCODE_QUERY: u8 = 0;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

pub const QR_QUERY: u8 = 0;
pub const QR_RESPONSE: u8 = 1;

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub qr: u8,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn encode(&self) -> Vec<u8> {
        let flags: u16 = (self.qr as u16) << 15
            | (self.opcode as u16) << 11
            | (self.aa as u16) << 10
            | (self.tc as u16) << 9
            | (self.rd as u16) << 8
            | (self.ra as u16) << 7
            | self.rcode as u16;
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 12 {
            bail!("DNS header too short");
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let header = Self {
            id,
            qr: ((flags >> 15) & 1) as u8,
            opcode: ((flags >> 11) & 0x0f) as u8,
            aa: (flags >> 10) & 1 == 1,
            tc: (flags >> 9) & 1 == 1,
            rd: (flags >> 8) & 1 == 1,
            ra: (flags >> 7) & 1 == 1,
            rcode: (flags & 0x0f) as u8,
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        };
        Ok((header, 12))
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = encode_name(&self.qname);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        let (qname, qname_len) = decode_name(data, 0)?;
        let offset = qname_len;
        if offset + 4 > data.len() {
            bail!("DNS question truncated after name");
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        Ok((
            Self {
                qname,
                qtype,
                qclass,
            },
            offset + 4,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    pub fn new_a(name: &str, ip: std::net::Ipv4Addr, ttl: u32) -> Self {
        Self {
            name: name.to_string(),
            rtype: TYPE_A,
            rclass: CLASS_IN,
            ttl,
            rdlength: 4,
            rdata: ip.octets().to_vec(),
        }
    }

    pub fn new_cname(name: &str, alias: &str, ttl: u32) -> Self {
        let rdata = encode_name(alias);
        let rdlength = rdata.len() as u16;
        Self {
            name: name.to_string(),
            rtype: TYPE_CNAME,
            rclass: CLASS_IN,
            ttl,
            rdlength,
            rdata,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = encode_name(&self.name);
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&self.rdlength.to_be_bytes());
        buf.extend_from_slice(&self.rdata);
        buf
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new_query(id: u16, rd: bool) -> Self {
        Self {
            header: DnsHeader {
                id,
                qr: QR_QUERY,
                opcode: OPCODE_QUERY,
                aa: false,
                tc: false,
                rd,
                ra: false,
                rcode: RCODE_NOERROR,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    pub fn new_response(query: &DnsPacket, rcode: u8) -> Self {
        Self {
            header: DnsHeader {
                id: query.header.id,
                qr: QR_RESPONSE,
                opcode: query.header.opcode,
                aa: true,
                tc: false,
                rd: query.header.rd,
                ra: true,
                rcode,
                qdcount: 0,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: query.questions.clone(),
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    pub fn add_answer(&mut self, record: DnsRecord) {
        self.header.ancount += 1;
        self.answers.push(record);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut header = self.header.clone();
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authorities.len() as u16;
        header.arcount = self.additionals.len() as u16;

        let mut buf = header.encode();
        for q in &self.questions {
            buf.extend_from_slice(&q.encode());
        }
        for r in &self.answers {
            buf.extend_from_slice(&r.encode());
        }
        for r in &self.authorities {
            buf.extend_from_slice(&r.encode());
        }
        for r in &self.additionals {
            buf.extend_from_slice(&r.encode());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let (header, mut offset) = DnsHeader::decode(data)?;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let (q, consumed) = DnsQuestion::decode(&data[offset..])?;
            offset += consumed;
            questions.push(q);
        }

        let answers = decode_records(data, &mut offset, header.ancount)?;
        let authorities = decode_records(data, &mut offset, header.nscount)?;
        let additionals = decode_records(data, &mut offset, header.arcount)?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn get_a_records(&self) -> Vec<(String, std::net::Ipv4Addr)> {
        self.answers
            .iter()
            .filter(|r| r.rtype == TYPE_A)
            .filter_map(|r| {
                if r.rdata.len() >= 4 {
                    Some((
                        r.name.clone(),
                        std::net::Ipv4Addr::new(r.rdata[0], r.rdata[1], r.rdata[2], r.rdata[3]),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_adblock_response(&self) -> bool {
        self.header.rcode == RCODE_NXDOMAIN
            || (self.header.ancount == 0 && self.header.rcode != RCODE_NOERROR)
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

fn decode_name(data: &[u8], start_offset: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start_offset;
    let mut jumped = false;
    let mut jump_offset = 0;

    loop {
        if offset >= data.len() {
            bail!("DNS name truncated at offset {offset}");
        }
        let len = data[offset];
        if len == 0 {
            offset += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= data.len() {
                bail!("DNS name pointer truncated");
            }
            let ptr = ((len as u16 & 0x3f) << 8) | data[offset + 1] as u16;
            if !jumped {
                offset += 2;
                jump_offset = offset;
            }
            offset = ptr as usize;
            jumped = true;
            continue;
        }
        if offset + 1 + len as usize > data.len() {
            bail!("DNS label truncated");
        }
        labels.push(
            std::str::from_utf8(&data[offset + 1..offset + 1 + len as usize])
                .map_err(|_| anyhow::anyhow!("invalid UTF-8 in DNS name"))?
                .to_string(),
        );
        offset += 1 + len as usize;
    }

    if !jumped {
        Ok((labels.join("."), offset - start_offset))
    } else {
        Ok((labels.join("."), jump_offset - start_offset))
    }
}

fn decode_record(data: &[u8], offset: &mut usize) -> Result<DnsRecord> {
    let (name, name_len) = decode_name(data, *offset)?;
    *offset += name_len;

    if *offset + 10 > data.len() {
        bail!("DNS record truncated at offset {offset}");
    }
    let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
    let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
    let ttl = u32::from_be_bytes([
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]);
    *offset += 10;

    if *offset + rdlength as usize > data.len() {
        bail!("DNS rdata truncated at offset {offset}");
    }
    let rdata = data[*offset..*offset + rdlength as usize].to_vec();
    *offset += rdlength as usize;

    Ok(DnsRecord {
        name,
        rtype,
        rclass,
        ttl,
        rdlength,
        rdata,
    })
}

fn decode_records(data: &[u8], offset: &mut usize, count: u16) -> Result<Vec<DnsRecord>> {
    let mut records = Vec::new();
    for _ in 0..count {
        records.push(decode_record(data, offset)?);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dns_header_encode_decode() {
        let header = DnsHeader {
            id: 0x1234,
            qr: QR_QUERY,
            opcode: OPCODE_QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            rcode: RCODE_NOERROR,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let encoded = header.encode();
        let (decoded, _) = DnsHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.id, 0x1234);
        assert_eq!(decoded.qr, QR_QUERY);
        assert!(decoded.rd);
        assert_eq!(decoded.qdcount, 1);
    }

    #[test]
    fn test_dns_name_encode_decode() {
        let name = "www.example.com";
        let encoded = encode_name(name);
        let (decoded, _) = decode_name(&encoded, 0).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn test_dns_question_encode_decode() {
        let q = DnsQuestion {
            qname: "test.example.com".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let encoded = q.encode();
        let (decoded, _) = DnsQuestion::decode(&encoded).unwrap();
        assert_eq!(decoded.qname, "test.example.com");
        assert_eq!(decoded.qtype, TYPE_A);
    }

    #[test]
    fn test_query_response_roundtrip() {
        let mut query = DnsPacket::new_query(0xabcd, true);
        query.questions.push(DnsQuestion {
            qname: "google.com".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });

        let encoded = query.encode();
        let decoded = DnsPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.header.id, 0xabcd);
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.questions[0].qname, "google.com");

        // Build response
        let mut resp = DnsPacket::new_response(&query, RCODE_NOERROR);
        resp.add_answer(DnsRecord::new_a(
            "google.com",
            Ipv4Addr::new(142, 250, 1, 1),
            300,
        ));

        let resp_encoded = resp.encode();
        let resp_decoded = DnsPacket::decode(&resp_encoded).unwrap();
        assert_eq!(resp_decoded.header.qr, QR_RESPONSE);
        assert_eq!(resp_decoded.answers.len(), 1);
        let a_records = resp_decoded.get_a_records();
        assert_eq!(a_records[0].1, Ipv4Addr::new(142, 250, 1, 1));
    }

    #[test]
    fn test_dns_name_with_pointer() {
        // Encoded: "example.com" then a pointer to "example.com"
        let name_bytes = encode_name("example.com");
        let mut compressed = name_bytes.clone();
        compressed.push(0xc0);
        compressed.push(0x00);

        let (decoded, consumed) = decode_name(&compressed, name_bytes.len()).unwrap();
        assert_eq!(decoded, "example.com");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_get_a_records_empty() {
        let pkt = DnsPacket::new_query(1, true);
        let records = pkt.get_a_records();
        assert!(records.is_empty());
    }

    #[test]
    fn test_dns_header_decode_too_short() {
        let result = DnsHeader::decode(&[0; 10]);
        assert!(result.is_err());
    }
}
