use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct CapturedPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
    pub timestamp: u64,
}

pub struct PacketSniffer { packets: Mutex<Vec<CapturedPacket>>, enabled: Mutex<bool> }

impl PacketSniffer {
    pub fn new() -> Self { Self { packets: Mutex::new(Vec::new()), enabled: Mutex::new(false) } }
    pub fn set_enabled(&self, val: bool) { *self.enabled.lock().unwrap() = val; }
    pub fn is_enabled(&self) -> bool { *self.enabled.lock().unwrap() }
    pub fn add_packet(&self, pkt: CapturedPacket) { self.packets.lock().unwrap().push(pkt); }
    pub fn get_packets(&self) -> Vec<CapturedPacket> { self.packets.lock().unwrap().clone() }
    pub fn clear(&self) { self.packets.lock().unwrap().clear(); }
}

impl Default for PacketSniffer { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sniffer() {
        let s = PacketSniffer::new();
        s.set_enabled(true);
        assert!(s.is_enabled());
        s.add_packet(CapturedPacket { src_ip: "10.0.0.1".into(), dst_ip: "8.8.8.8".into(), src_port: 12345, dst_port: 443, protocol: 6, length: 64, timestamp: 0 });
        assert_eq!(s.get_packets().len(), 1);
    }
}
