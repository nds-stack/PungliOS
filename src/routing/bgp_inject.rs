use crate::routing::{DynamicRoute, RoutingProtocol};
use anyhow::Result;

pub struct BgpRouteInjector {
    routes: std::sync::Mutex<Vec<DynamicRoute>>,
}

impl BgpRouteInjector {
    pub fn new() -> Self {
        Self {
            routes: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn inject_route(
        &self,
        destination: &str,
        prefix: u8,
        nexthop: &str,
        metric: u32,
    ) -> Result<DynamicRoute> {
        if destination.is_empty() {
            anyhow::bail!("destination cannot be empty");
        }
        if prefix > 128 {
            anyhow::bail!("prefix must be <= 128");
        }

        let route = DynamicRoute {
            destination: destination.to_string(),
            prefix,
            nexthop: nexthop.to_string(),
            metric,
            protocol: RoutingProtocol::Bgp,
            age_secs: 0,
            interface: None,
        };

        let mut routes = self.routes.lock().unwrap();
        routes.push(route.clone());
        Ok(route)
    }

    pub fn withdraw_route(&self, destination: &str, prefix: u8) -> Result<()> {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|r| !(r.destination == destination && r.prefix == prefix));
        Ok(())
    }

    pub fn get_routes(&self) -> Vec<DynamicRoute> {
        self.routes.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.routes.lock().unwrap().clear();
    }
}

impl Default for BgpRouteInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_route() {
        let injector = BgpRouteInjector::new();
        let route = injector.inject_route("10.0.0.0", 24, "192.168.1.1", 100).unwrap();
        assert_eq!(route.destination, "10.0.0.0");
        assert_eq!(route.prefix, 24);
        assert_eq!(route.protocol, RoutingProtocol::Bgp);
    }

    #[test]
    fn test_withdraw_route() {
        let injector = BgpRouteInjector::new();
        injector.inject_route("10.0.0.0", 24, "192.168.1.1", 100).unwrap();
        assert_eq!(injector.get_routes().len(), 1);
        injector.withdraw_route("10.0.0.0", 24).unwrap();
        assert!(injector.get_routes().is_empty());
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        let injector = BgpRouteInjector::new();
        assert!(injector.inject_route("10.0.0.0", 200, "1.1.1.1", 100).is_err());
    }
}
