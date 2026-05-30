use crate::routing::{DynamicRoute, RoutingProtocol};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct Lsa {
    pub lsa_type: u8,
    pub lsa_id: u32,
    pub advertising_router: u32,
    pub sequence_number: u32,
    pub age: u16,
    pub link_state_id: String,
    pub data: Vec<u8>,
}

pub struct OspfSpf {
    lsdb: Mutex<HashMap<(u32, u32), Lsa>>,
    routes: Mutex<Vec<DynamicRoute>>,
}

impl OspfSpf {
    pub fn new() -> Self {
        Self {
            lsdb: Mutex::new(HashMap::new()),
            routes: Mutex::new(Vec::new()),
        }
    }

    pub fn add_lsa(&self, lsa: Lsa) -> Result<()> {
        let key = (lsa.lsa_type as u32, lsa.lsa_id);
        self.lsdb.lock().unwrap().insert(key, lsa);
        Ok(())
    }

    pub fn remove_lsa(&self, lsa_type: u8, lsa_id: u32) {
        self.lsdb.lock().unwrap().remove(&(lsa_type as u32, lsa_id));
    }

    pub fn get_lsdb_size(&self) -> usize {
        self.lsdb.lock().unwrap().len()
    }

    pub fn run_spf(&self) -> Result<Vec<DynamicRoute>> {
        let lsdb = self.lsdb.lock().unwrap();
        let mut routes = self.routes.lock().unwrap();
        routes.clear();

        // Simplified SPF: iterate LSAs and generate routes
        for ((type_, id), lsa) in lsdb.iter() {
            let _ = type_;
            let _ = id;
            // Router LSA (type 1): generate connected routes
            if lsa.lsa_type == 1 {
                let router_ip = format!(
                    "{}.{}.{}.{}",
                    (lsa.advertising_router >> 24) & 0xff,
                    (lsa.advertising_router >> 16) & 0xff,
                    (lsa.advertising_router >> 8) & 0xff,
                    lsa.advertising_router & 0xff,
                );
                routes.push(DynamicRoute {
                    destination: router_ip,
                    prefix: 32,
                    nexthop: "0.0.0.0".into(),
                    metric: 10,
                    protocol: RoutingProtocol::Ospf,
                    age_secs: lsa.age as u64,
                    interface: None,
                });
            }
        }

        Ok(routes.clone())
    }

    pub fn get_routes(&self) -> Vec<DynamicRoute> {
        self.routes.lock().unwrap().clone()
    }
}

impl Default for OspfSpf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lsdb_add() {
        let spf = OspfSpf::new();
        spf.add_lsa(Lsa {
            lsa_type: 1,
            lsa_id: 0x0a000001,
            advertising_router: 0x0a000001,
            sequence_number: 0x80000001,
            age: 10,
            link_state_id: "10.0.0.1".into(),
            data: vec![],
        })
        .unwrap();
        assert_eq!(spf.get_lsdb_size(), 1);
    }

    #[test]
    fn test_spf_run() {
        let spf = OspfSpf::new();
        spf.add_lsa(Lsa {
            lsa_type: 1,
            lsa_id: 0x0a000001,
            advertising_router: 0x0a000001,
            sequence_number: 0x80000001,
            age: 10,
            link_state_id: "10.0.0.1".into(),
            data: vec![],
        })
        .unwrap();
        let routes = spf.run_spf().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].protocol, RoutingProtocol::Ospf);
    }
}
