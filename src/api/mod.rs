#![cfg(feature = "api")]

pub(crate) mod handlers;
pub(crate) mod monitoring;

use crate::traits::MockBackend;
use crate::{conntrack, firewall, net, qos, routing, user, wireguard};
use axum::{
    Json, Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

#[derive(Clone)]
pub struct AppState {
    pub iface_mgr: Arc<net::iface::InterfaceManager<MockBackend>>,
    pub fw_mgr: Arc<firewall::FirewallManager<MockBackend>>,
    pub nat_mgr: Arc<firewall::nat::NatManager<MockBackend>>,
    pub route_mgr: Arc<net::route::RouteManager<MockBackend>>,
    pub qos_mgr: Arc<qos::QosManager<MockBackend>>,
    pub ct_mgr: Arc<Mutex<conntrack::ConntrackManager<MockBackend>>>,
    pub user_mgr: Arc<user::UserManager<user::MockUserBackend>>,
    pub routing_mgr: Arc<routing::DynamicRoutingManager<routing::MockDynamicRouting>>,
    pub wg_mgr: Arc<wireguard::WireGuardManager<wireguard::MockWireguardBackend>>,
    pub monitoring_tx: broadcast::Sender<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let backend = MockBackend::new();
        let user_backend = user::MockUserBackend::new();
        let (monitoring_tx, _) = broadcast::channel(16);
        Self {
            iface_mgr: Arc::new(net::iface::InterfaceManager::new(backend.clone())),
            fw_mgr: Arc::new(firewall::FirewallManager::new(backend.clone())),
            nat_mgr: Arc::new(firewall::nat::NatManager::new(backend.clone())),
            route_mgr: Arc::new(net::route::RouteManager::new(backend.clone())),
            qos_mgr: Arc::new(qos::QosManager::new(backend.clone())),
            ct_mgr: Arc::new(Mutex::new(conntrack::ConntrackManager::new(
                backend.clone(),
            ))),
            user_mgr: Arc::new(user::UserManager::new(user_backend)),
            routing_mgr: Arc::new(routing::DynamicRoutingManager::new(
                routing::MockDynamicRouting::new(),
            )),
            wg_mgr: Arc::new(wireguard::WireGuardManager::new(
                wireguard::MockWireguardBackend::new(),
            )),
            monitoring_tx,
        }
    }

    pub fn start_monitoring(&self) {
        let app = self.clone();
        let tx = self.monitoring_tx.clone();
        tokio::spawn(async move {
            monitoring::monitoring_loop(app, tx).await;
        });
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/interfaces", get(handlers::list_interfaces))
        .route("/api/v1/interfaces", post(handlers::create_interface))
        .route("/api/v1/interfaces/{name}", get(handlers::get_interface))
        .route(
            "/api/v1/interfaces/{name}/up",
            post(handlers::set_interface_up),
        )
        .route(
            "/api/v1/interfaces/{name}/down",
            post(handlers::set_interface_down),
        )
        .route(
            "/api/v1/interfaces/{name}/mtu",
            put(handlers::set_interface_mtu),
        )
        .route("/api/v1/firewall/rules", get(handlers::list_rules))
        .route("/api/v1/firewall/rules", post(handlers::add_rule))
        .route(
            "/api/v1/firewall/rules/{handle}",
            delete(handlers::delete_rule),
        )
        .route("/api/v1/firewall/flush", post(handlers::flush_rules))
        .route("/api/v1/nat/rules", get(handlers::list_nat_rules))
        .route("/api/v1/nat/rules", post(handlers::add_nat_rule))
        .route(
            "/api/v1/nat/rules/{handle}",
            delete(handlers::delete_nat_rule),
        )
        .route("/api/v1/routes", get(handlers::list_routes))
        .route("/api/v1/routes", post(handlers::add_route))
        .route("/api/v1/routes/del", post(handlers::delete_route))
        .route("/api/v1/qos/attach", post(handlers::attach_qdisc))
        .route("/api/v1/qos/classes", get(handlers::list_classes))
        .route("/api/v1/qos/classes", post(handlers::add_class))
        .route(
            "/api/v1/qos/classes/{classid}",
            delete(handlers::delete_class),
        )
        .route(
            "/api/v1/conntrack/stats",
            get(handlers::get_conntrack_stats),
        )
        .route("/api/v1/conntrack/max", put(handlers::set_conntrack_max))
        .route("/api/v1/routing/bgp/peers", get(handlers::list_bgp_peers))
        .route("/api/v1/routing/bgp/peers", post(handlers::add_bgp_peer))
        .route(
            "/api/v1/routing/bgp/peers/{ip}",
            delete(handlers::remove_bgp_peer),
        )
        .route("/api/v1/routing/bgp/status", get(handlers::get_bgp_status))
        .route("/api/v1/routing/ospf/areas", get(handlers::list_ospf_areas))
        .route("/api/v1/routing/ospf/areas", post(handlers::add_ospf_area))
        .route(
            "/api/v1/routing/ospf/areas/{id}",
            delete(handlers::remove_ospf_area),
        )
        .route(
            "/api/v1/routing/ospf/status",
            get(handlers::get_ospf_status),
        )
        .route("/api/v1/routing/table", get(handlers::list_dynamic_routes))
        .route(
            "/api/v1/wireguard/interfaces",
            get(handlers::list_wg_interfaces),
        )
        .route(
            "/api/v1/wireguard/interfaces",
            post(handlers::create_wg_interface),
        )
        .route(
            "/api/v1/wireguard/interfaces/{name}",
            delete(handlers::delete_wg_interface),
        )
        .route(
            "/api/v1/wireguard/interfaces/{name}/peers",
            get(handlers::list_wg_peers),
        )
        .route(
            "/api/v1/wireguard/interfaces/{name}/peers",
            post(handlers::add_wg_peer),
        )
        .route(
            "/api/v1/wireguard/interfaces/{name}/peers/{pubkey}",
            delete(handlers::remove_wg_peer),
        )
        .route("/api/v1/wireguard/status", get(handlers::get_wg_status))
        .route("/api/v1/users", get(handlers::list_users))
        .route("/api/v1/users", post(handlers::create_user))
        .route("/api/v1/users/{username}", put(handlers::update_user))
        .route("/api/v1/users/{username}", delete(handlers::delete_user))
        .route("/api/v1/packages", get(handlers::list_packages))
        .route("/api/v1/packages", post(handlers::create_package))
        .route("/api/v1/packages/{name}", put(handlers::update_package))
        .route("/api/v1/packages/{name}", delete(handlers::delete_package))
        .route("/api/v1/health", get(handlers::health_check))
        .route("/api/v1/monitoring/bandwidth", get(handlers::get_bandwidth))
        .route("/api/v1/monitoring/system", get(handlers::get_system_stats))
        .route(
            "/api/v1/monitoring/stream",
            get(monitoring::monitoring_stream),
        )
        .with_state(state)
}

pub(crate) fn ok() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

pub(crate) fn err(msg: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"error": msg}))
}

pub(crate) fn json_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

pub(crate) fn json_bool(v: &serde_json::Value) -> Option<bool> {
    v.as_bool().or_else(|| match v.as_str() {
        Some("on" | "true" | "1") => Some(true),
        Some(_) => Some(false),
        None => None,
    })
}

pub(crate) fn json_str_array(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                .collect()
        })
        .or_else(|| {
            v.as_str().map(|s| {
                s.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        })
        .unwrap_or_default()
}
