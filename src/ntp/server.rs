use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtpConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub stratum: u8,
    pub reference: String,
}

impl Default for NtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 123,
            stratum: 3,
            reference: "PungliOS".into(),
        }
    }
}

pub struct NtpServer {
    config: Mutex<NtpConfig>,
    start_time: std::time::Instant,
}

impl NtpServer {
    pub fn new() -> Self {
        Self {
            config: Mutex::new(NtpConfig::default()),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn get_config(&self) -> NtpConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, config: NtpConfig) -> Result<()> {
        if config.stratum < 1 || config.stratum > 15 {
            bail!("stratum must be 1-15");
        }
        let mut c = self.config.lock().unwrap();
        *c = config;
        Ok(())
    }

    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn current_timestamp(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
}

impl Default for NtpServer {
    fn default() -> Self {
        Self::new()
    }
}

// NTP packet constants
#[allow(dead_code)]
pub const NTP_PORT: u16 = 123;
#[allow(dead_code)]
pub const NTP_VERSION: u8 = 4;
#[allow(dead_code)]
pub const NTP_MODE_SERVER: u8 = 4;

#[derive(Debug, Clone)]
pub struct NtpPacket {
    pub li: u8,
    pub vn: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_ts: u64,
    pub originate_ts: u64,
    pub receive_ts: u64,
    pub transmit_ts: u64,
}

impl NtpPacket {
    pub fn encode(&self) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0] = (self.li << 6) | (self.vn << 3) | self.mode;
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        buf[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id.to_be_bytes());
        buf[16..24].copy_from_slice(&self.reference_ts.to_be_bytes());
        buf[24..32].copy_from_slice(&self.originate_ts.to_be_bytes());
        buf[32..40].copy_from_slice(&self.receive_ts.to_be_bytes());
        buf[40..48].copy_from_slice(&self.transmit_ts.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            bail!("NTP packet too short");
        }
        Ok(Self {
            li: (data[0] >> 6) & 0x03,
            vn: (data[0] >> 3) & 0x07,
            mode: data[0] & 0x07,
            stratum: data[1],
            poll: data[2] as i8,
            precision: data[3] as i8,
            root_delay: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            root_dispersion: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            reference_id: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            reference_ts: u64::from_be_bytes([
                data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
            ]),
            originate_ts: u64::from_be_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            receive_ts: u64::from_be_bytes([
                data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
            ]),
            transmit_ts: u64::from_be_bytes([
                data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
            ]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_config() {
        let srv = NtpServer::new();
        assert!(!srv.get_config().enabled);
        assert_eq!(srv.get_config().stratum, 3);
    }

    #[test]
    fn test_ntp_packet_roundtrip() {
        let packet = NtpPacket {
            li: 0,
            vn: 4,
            mode: 4,
            stratum: 3,
            poll: 6,
            precision: -18,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_ts: 0,
            originate_ts: 0,
            receive_ts: 0,
            transmit_ts: 0,
        };
        let encoded = packet.encode();
        let decoded = NtpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.vn, 4);
        assert_eq!(decoded.mode, 4);
        assert_eq!(decoded.stratum, 3);
    }

    #[test]
    fn test_uptime() {
        let srv = NtpServer::new();
        assert!(srv.uptime_secs() >= 0);
    }
}
