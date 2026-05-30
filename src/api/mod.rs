#![cfg(feature = "api")]

pub(crate) mod handlers;
pub(crate) mod monitoring;

use crate::traits::MockBackend;
use crate::{
    address_list, billing, bpf_qos, conntrack, dhcp_client, firewall, net, plugins, pppoe, qos,
    routing, scheduler, tenancy, user, vrrp, wireguard,
};
use axum::{
    Json, Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};

/// Shared application state holding all manager instances.
///
/// Passed to every API handler via Axum's `State` extractor.
/// All managers use mock backends by default for development/testing.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
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
    pub billing_mgr: Arc<billing::BillingManager<billing::MockBillingBackend>>,
    pub failover_mgr: Arc<pppoe::failover::PppFailoverManager<pppoe::failover::MockPppFailover>>,
    pub vrrp_mgr: Arc<vrrp::VrrpManager<vrrp::MockVrrp>>,
    pub bpf_qos_mgr: Arc<bpf_qos::BpfQosManager<bpf_qos::MockBpfQos>>,
    pub plugin_mgr: Arc<plugins::PluginManager>,
    pub tenancy_mgr: Arc<tenancy::TenancyManager<tenancy::MockTenancy>>,
    pub address_list_mgr: Arc<address_list::AddressListManager>,
    pub dhcp_client_mgr: Arc<dhcp_client::DhcpClientManager<dhcp_client::MockDhcpClient>>,
    pub scheduler_mgr: Arc<scheduler::ScheduledTaskManager>,
    pub monitoring_tx: broadcast::Sender<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Creates a new AppState with all mock backends initialized.
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
            billing_mgr: Arc::new(billing::BillingManager::new(
                billing::MockBillingBackend::new(),
            )),
            failover_mgr: Arc::new(pppoe::failover::PppFailoverManager::new(
                pppoe::failover::MockPppFailover::new(),
            )),
            vrrp_mgr: Arc::new(vrrp::VrrpManager::new(vrrp::MockVrrp::new())),
            bpf_qos_mgr: Arc::new(bpf_qos::BpfQosManager::new(bpf_qos::MockBpfQos::new())),
            plugin_mgr: Arc::new(plugins::PluginManager::new()),
            tenancy_mgr: Arc::new(tenancy::TenancyManager::new(tenancy::MockTenancy::new())),
            address_list_mgr: Arc::new(address_list::AddressListManager::new()),
            dhcp_client_mgr: Arc::new(dhcp_client::DhcpClientManager::new(
                dhcp_client::MockDhcpClient,
            )),
            scheduler_mgr: Arc::new(scheduler::ScheduledTaskManager::new()),
            monitoring_tx,
        }
    }

    /// Spawns a background task that polls system stats every 2 seconds
    /// and broadcasts them via the monitoring SSE channel.
    pub fn start_monitoring(&self) {
        let app = self.clone();
        let tx = self.monitoring_tx.clone();
        tokio::spawn(async move {
            monitoring::monitoring_loop(app, tx).await;
        });
    }
}

/// Builds the Axum HTTP router with all API and monitoring routes.
///
/// Features 40+ endpoints covering: interfaces, firewall, NAT, routes,
/// QoS, conntrack, users, packages, BGP, OSPF, WireGuard, monitoring, health.
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
            "/api/v1/qos/classes/{iface}/{classid}",
            delete(handlers::delete_class),
        )
        .route(
            "/api/v1/conntrack/stats",
            get(handlers::get_conntrack_stats),
        )
        .route("/api/v1/conntrack/max", put(handlers::set_conntrack_max))
        .route(
            "/api/v1/conntrack/top-talkers",
            get(handlers::get_top_talkers),
        )
        .route(
            "/api/v1/conntrack/protocols",
            get(handlers::get_protocol_distribution),
        )
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
        .route("/api/v1/billing/plans", get(handlers::list_billing_plans))
        .route("/api/v1/billing/plans", post(handlers::create_billing_plan))
        .route("/api/v1/billing/invoices", get(handlers::list_invoices))
        .route("/api/v1/billing/invoices", post(handlers::generate_invoice))
        .route(
            "/api/v1/billing/invoices/{id}/pay",
            post(handlers::mark_invoice_paid),
        )
        .route(
            "/api/v1/billing/summary",
            get(handlers::get_billing_summary),
        )
        .route("/api/v1/failover/uplinks", get(handlers::list_uplinks))
        .route("/api/v1/failover/uplinks", post(handlers::add_uplink))
        .route(
            "/api/v1/failover/uplinks/{name}",
            delete(handlers::remove_uplink),
        )
        .route(
            "/api/v1/failover/status",
            get(handlers::get_failover_status),
        )
        .route("/api/v1/failover/trigger", post(handlers::trigger_failover))
        .route("/api/v1/vrrp/instances", get(handlers::list_vrrp_instances))
        .route(
            "/api/v1/vrrp/instances",
            post(handlers::create_vrrp_instance),
        )
        .route(
            "/api/v1/vrrp/instances/{name}",
            delete(handlers::delete_vrrp_instance),
        )
        .route("/api/v1/vrrp/status", get(handlers::get_vrrp_status))
        .route("/api/v1/bpf-qos/qdiscs", get(handlers::list_bpf_qdiscs))
        .route("/api/v1/bpf-qos/qdiscs", post(handlers::attach_bpf_qdisc))
        .route(
            "/api/v1/bpf-qos/qdiscs/{iface}",
            delete(handlers::detach_bpf_qdisc),
        )
        .route("/api/v1/bpf-qos/status", get(handlers::get_bpf_qos_status))
        .route("/api/v1/plugins", get(handlers::list_plugins))
        .route("/api/v1/plugins/status", get(handlers::get_plugin_status))
        .route("/api/v1/tenants", get(handlers::list_tenants))
        .route("/api/v1/tenants", post(handlers::create_tenant))
        .route("/api/v1/tenants/{id}", delete(handlers::delete_tenant))
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
        .route("/api/v1/address-lists", get(handlers::list_all_address_lists))
        .route(
            "/api/v1/address-lists",
            post(handlers::add_address_list),
        )
        .route(
            "/api/v1/address-lists/{name}",
            get(handlers::list_address_list),
        )
        .route(
            "/api/v1/address-lists/entry/{id}",
            delete(handlers::remove_address_list_entry),
        )
        .route(
            "/api/v1/address-lists/{name}/flush",
            post(handlers::flush_address_list),
        )
        .route(
            "/api/v1/tools/ping",
            get(handlers::tools_ping),
        )
        .route(
            "/api/v1/tools/traceroute",
            get(handlers::tools_traceroute),
        )
        .route(
            "/api/v1/dhcp-client/{interface}/discover",
            post(handlers::dhcp_client_discover),
        )
        .route(
            "/api/v1/dhcp-client/{interface}/status",
            get(handlers::dhcp_client_status),
        )
        .route(
            "/api/v1/dhcp-client/{interface}/release",
            post(handlers::dhcp_client_release),
        )
        .route("/api/v1/scheduler/tasks", get(handlers::list_scheduler_tasks))
        .route("/api/v1/scheduler/tasks", post(handlers::create_scheduler_task))
        .route(
            "/api/v1/scheduler/tasks/{id}",
            get(handlers::get_scheduler_task),
        )
        .route(
            "/api/v1/scheduler/tasks/{id}",
            delete(handlers::delete_scheduler_task),
        )
        .route(
            "/api/v1/scheduler/tasks/{id}/toggle",
            post(handlers::toggle_scheduler_task),
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
