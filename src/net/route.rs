use anyhow::{bail, Result};
use std::net::IpAddr;
use crate::traits::{NetlinkRoute, Route};

pub struct RouteManager<T: NetlinkRoute> {
    backend: T,
}

impl<T: NetlinkRoute> RouteManager<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &T {
        &self.backend
    }

    pub async fn add_route(&self, route: &Route) -> Result<()> {
        if route.prefix > 128 {
            bail!("prefix length must be ≤ 128, got {}", route.prefix);
        }
        self.backend.add_route(route).await
    }

    pub async fn delete_route(&self, destination: IpAddr, prefix: u8) -> Result<()> {
        if prefix > 128 {
            bail!("prefix length must be ≤ 128, got {prefix}");
        }
        self.backend.delete_route(destination, prefix).await
    }

    pub async fn list_routes(&self) -> Result<Vec<Route>> {
        self.backend.list_routes().await
    }

    pub fn add_default_via(&self, nexthop: IpAddr) -> Route {
        Route {
            destination: "0.0.0.0".parse().unwrap(),
            prefix: 0,
            nexthop: Some(nexthop),
            iface: None,
            metric: Some(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::MockBackend;

    fn setup() -> RouteManager<MockBackend> {
        RouteManager::new(MockBackend::new())
    }

    #[tokio::test]
    async fn test_add_route() {
        let mgr = setup();
        let route = Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 24,
            nexthop: Some("192.168.1.1".parse().unwrap()),
            iface: Some("eth0".into()),
            metric: Some(100),
        };
        mgr.add_route(&route).await.unwrap();
        let routes = mgr.list_routes().await.unwrap();
        assert_eq!(routes.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_route() {
        let mgr = setup();
        mgr.add_route(&Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 24,
            nexthop: None,
            iface: None,
            metric: None,
        }).await.unwrap();
        mgr.delete_route("10.0.0.0".parse().unwrap(), 24).await.unwrap();
        assert!(mgr.list_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_routes_empty() {
        let mgr = setup();
        assert!(mgr.list_routes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_invalid_prefix_rejected() {
        let mgr = setup();
        let err = mgr.add_route(&Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 200,
            nexthop: None,
            iface: None,
            metric: None,
        }).await.unwrap_err();
        assert!(err.to_string().contains("≤ 128"));
    }

    #[tokio::test]
    async fn test_default_route_helper() {
        let mgr = setup();
        let route = mgr.add_default_via("192.168.1.1".parse().unwrap());
        assert_eq!(route.prefix, 0);
        assert_eq!(route.destination.to_string(), "0.0.0.0");
    }

    #[tokio::test]
    async fn test_multiple_routes() {
        let mgr = setup();
        mgr.add_route(&Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 24,
            nexthop: None,
            iface: None,
            metric: None,
        }).await.unwrap();
        mgr.add_route(&Route {
            destination: "172.16.0.0".parse().unwrap(),
            prefix: 16,
            nexthop: None,
            iface: None,
            metric: None,
        }).await.unwrap();
        assert_eq!(mgr.list_routes().await.unwrap().len(), 2);
    }
}
