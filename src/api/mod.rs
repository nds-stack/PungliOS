#![cfg(feature = "api")]

pub(crate) mod handlers;
pub(crate) mod monitoring;

use crate::traits::MockBackend;
use crate::{
    accounting, address_list, backup, billing, bonding, bpf_qos, bridge, cloud, conntrack, dhcp,
    dhcp_client, dns, dot1x, firewall, graphs, health, hotspot, ipsec, ipv6, l2tp, lldp, lte, mpls,
    net, netwatch, ntp, plugins, pppoe, qos, radius, routing, scheduler, snmp, ssh, syslog, tenancy,
    tools, traffic_flow, tunnel, upgrade, upnp, user, vrf, vrrp, watchdog, wireguard,
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
    pub bond_mgr: Arc<bonding::BondingManager<bonding::MockBondingBackend>>,
    pub route_filter_mgr: Arc<routing::RouteFilterManager>,
    pub bridge_vlan_mgr: Arc<net::bridge_vlan::BridgeVlanManager>,
    pub vrf_mgr: Arc<vrf::VrfManager<vrf::MockVrfBackend>>,
    pub l2tp_mgr: Arc<l2tp::L2tpManager<l2tp::MockL2tpBackend>>,
    pub netwatch_mgr: Arc<netwatch::NetwatchManager>,
    pub pcq_mgr: Arc<bpf_qos::PcqManager>,
    pub snmp_agent: Arc<snmp::SnmpAgent>,
    pub ipsec_mgr: Arc<ipsec::IpsecManager>,
    pub ntp_srv: Arc<ntp::NtpServer>,
    pub graph_store: Arc<graphs::GraphStore>,
    pub hotspot_sessions: Arc<hotspot::SessionManager>,
    pub hotspot_walled_garden: Arc<hotspot::WalledGarden>,
    pub bgp_injector: Arc<routing::BgpRouteInjector>,
    pub ospf_spf: Arc<routing::OspfSpf>,
    pub lte_mgr: Arc<lte::ModemManager>,
    pub ipv6_dhcp_mgr: Arc<ipv6::Dhcpv6Manager<ipv6::MockDhcpv6Backend>>,
    pub ipv6_radvd_mgr: Arc<ipv6::RadvdManager>,
    pub ipv6_firewall: Arc<ipv6::Ipv6Firewall>,
    pub dhcp_relay_mgr: Arc<dhcp::relay::DhcpRelayManager>,
    pub dhcp_snooping: Arc<dhcp::snooping::DhcpSnooping>,
    pub igmp_snooping: Arc<bridge::igmp::IgmpSnooping>,
    pub bridge_stp_mgr: Arc<bridge::stp::StpManager>,
    pub bridge_acl: Arc<bridge::filter::BridgeAcl>,
    pub lldp_agent: Arc<lldp::LldpAgent>,
    pub bfd_mgr: Arc<routing::BfdManager>,
    pub dns_static_mgr: Arc<dns::DnsStaticManager>,
    pub ntp_client: Arc<ntp::NtpClient>,
    pub mangle_table: Arc<firewall::MangleTable>,
    pub pbr_mgr: Arc<routing::PbrManager>,
    pub eoip_mgr: Arc<tunnel::EoipManager>,
    pub gre_mgr: Arc<tunnel::GreManager>,
    pub flow_exporter: Arc<traffic_flow::FlowExporter>,
    pub wol_mgr: Arc<tools::WolManager>,
    pub mpls_mgr: Arc<mpls::MplsManager>,
    pub rip_mgr: Arc<routing::RipManager>,
    pub ospfv3_mgr: Arc<routing::Ospfv3Manager>,
    pub traffic_gen: bool,
    pub sniffer: Arc<tools::PacketSniffer>,
    pub radius_coa: Arc<radius::coa::RadiusCoa>,
    pub backup_mgr: Arc<backup::BackupManager>,
    pub email_mgr: Arc<tools::EmailManager>,
    pub upnp_mgr: Arc<upnp::UpnpManager>,
    pub dot1x_mgr: Arc<dot1x::Dot1xManager>,
    pub ddns_mgr: Arc<cloud::DdnsManager>,
    pub health_mon: Arc<health::HealthMonitor>,
    pub ip_accounting: Arc<accounting::IpAccounting>,
    pub layer7_mgr: Arc<firewall::Layer7Manager>,
    pub ssh_mgr: Arc<ssh::SshManager>,
    pub syslog_srv: Arc<syslog::SyslogServer>,
    pub dhcpv6_relay_mgr: Arc<ipv6::Dhcpv6RelayManager>,
    pub proxy_arp_mgr: Arc<net::proxy_arp::ProxyArpManager>,
    pub bridge_isolation: Arc<bridge::isolation::PortIsolation>,
    pub igmp_proxy_mgr: Arc<bridge::igmp_proxy::IgmpProxyManager>,
    pub burst_mgr: Arc<qos::BurstManager>,
    pub dhcp_radius_mgr: Arc<dhcp::radius::DhcpRadiusManager>,
    pub mndp_mgr: Arc<lldp::mndp::MndpManager>,
    pub upgrade_mgr: Arc<upgrade::UpgradeManager>,
    pub watchdog_mgr: Arc<watchdog::WatchdogManager>,
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
            bond_mgr: Arc::new(bonding::BondingManager::new(
                bonding::MockBondingBackend::new(),
            )),
            route_filter_mgr: Arc::new(routing::RouteFilterManager::new()),
            bridge_vlan_mgr: Arc::new(net::bridge_vlan::BridgeVlanManager::new()),
            vrf_mgr: Arc::new(vrf::VrfManager::new(vrf::MockVrfBackend::new())),
            l2tp_mgr: Arc::new(l2tp::L2tpManager::new(l2tp::MockL2tpBackend::new())),
            netwatch_mgr: Arc::new(netwatch::NetwatchManager::new()),
            pcq_mgr: Arc::new(bpf_qos::PcqManager::new()),
            snmp_agent: Arc::new(snmp::SnmpAgent::new()),
            ipsec_mgr: Arc::new(ipsec::IpsecManager::new()),
            ntp_srv: Arc::new(ntp::NtpServer::new()),
            graph_store: Arc::new(graphs::GraphStore::new(288, 300)),
            hotspot_sessions: Arc::new(hotspot::SessionManager::new()),
            hotspot_walled_garden: Arc::new(hotspot::WalledGarden::new()),
            bgp_injector: Arc::new(routing::BgpRouteInjector::new()),
            ospf_spf: Arc::new(routing::OspfSpf::new()),
            lte_mgr: Arc::new(lte::ModemManager::new()),
            ipv6_dhcp_mgr: Arc::new(ipv6::Dhcpv6Manager::new(ipv6::MockDhcpv6Backend::new())),
            ipv6_radvd_mgr: Arc::new(ipv6::RadvdManager::new()),
            ipv6_firewall: Arc::new(ipv6::Ipv6Firewall::new()),
            dhcp_relay_mgr: Arc::new(dhcp::relay::DhcpRelayManager::new()),
            dhcp_snooping: Arc::new(dhcp::snooping::DhcpSnooping::new()),
            igmp_snooping: Arc::new(bridge::igmp::IgmpSnooping::new()),
            bridge_stp_mgr: Arc::new(bridge::stp::StpManager::new()),
            bridge_acl: Arc::new(bridge::filter::BridgeAcl::new()),
            lldp_agent: Arc::new(lldp::LldpAgent::new()),
            bfd_mgr: Arc::new(routing::BfdManager::new()),
            dns_static_mgr: Arc::new(crate::dns::DnsStaticManager::new()),
            ntp_client: Arc::new(ntp::NtpClient::new()),
            mangle_table: Arc::new(firewall::MangleTable::new()),
            pbr_mgr: Arc::new(routing::PbrManager::new()),
            eoip_mgr: Arc::new(tunnel::EoipManager::new()),
            gre_mgr: Arc::new(tunnel::GreManager::new()),
            flow_exporter: Arc::new(traffic_flow::FlowExporter::new()),
            wol_mgr: Arc::new(tools::WolManager::new()),
            mpls_mgr: Arc::new(mpls::MplsManager::new()),
            rip_mgr: Arc::new(routing::RipManager::new()),
            ospfv3_mgr: Arc::new(routing::Ospfv3Manager::new()),
            traffic_gen: false,
            sniffer: Arc::new(tools::PacketSniffer::new()),
            radius_coa: Arc::new(radius::coa::RadiusCoa::new("127.0.0.1", "secret", 3799)),
            backup_mgr: Arc::new(backup::BackupManager::new()),
            email_mgr: Arc::new(tools::EmailManager::new()),
            upnp_mgr: Arc::new(upnp::UpnpManager::new()),
            dot1x_mgr: Arc::new(dot1x::Dot1xManager::new()),
            ddns_mgr: Arc::new(cloud::DdnsManager::new()),
            health_mon: Arc::new(health::HealthMonitor::new()),
            ip_accounting: Arc::new(accounting::IpAccounting::new()),
            layer7_mgr: Arc::new(firewall::Layer7Manager::new()),
            ssh_mgr: Arc::new(ssh::SshManager::new()),
            syslog_srv: Arc::new(syslog::SyslogServer::new()),
            dhcpv6_relay_mgr: Arc::new(ipv6::Dhcpv6RelayManager::new()),
            proxy_arp_mgr: Arc::new(net::proxy_arp::ProxyArpManager::new()),
            bridge_isolation: Arc::new(bridge::isolation::PortIsolation::new()),
            igmp_proxy_mgr: Arc::new(bridge::igmp_proxy::IgmpProxyManager::new()),
            burst_mgr: Arc::new(qos::BurstManager::new()),
            dhcp_radius_mgr: Arc::new(dhcp::radius::DhcpRadiusManager::new()),
            mndp_mgr: Arc::new(lldp::MndpManager::new()),
            upgrade_mgr: Arc::new(upgrade::UpgradeManager::new()),
            watchdog_mgr: Arc::new(watchdog::WatchdogManager::new()),
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
        .route("/api/v1/bonding/bonds", get(handlers::list_bonds))
        .route("/api/v1/bonding/bonds", post(handlers::create_bond))
        .route(
            "/api/v1/bonding/bonds/{name}",
            get(handlers::get_bond),
        )
        .route(
            "/api/v1/bonding/bonds/{name}",
            delete(handlers::delete_bond),
        )
        .route(
            "/api/v1/bonding/bonds/{name}/slaves",
            post(handlers::add_bond_slave),
        )
        .route(
            "/api/v1/bonding/bonds/{name}/slaves/{slave}",
            delete(handlers::remove_bond_slave),
        )
        .route("/api/v1/bonding/status", get(handlers::bond_status))
        .route(
            "/api/v1/routing/filters/prefix-lists",
            get(handlers::list_prefix_lists),
        )
        .route(
            "/api/v1/routing/filters/prefix-lists",
            post(handlers::add_prefix_list_entry),
        )
        .route(
            "/api/v1/routing/filters/prefix-lists/{name}",
            get(handlers::get_prefix_list),
        )
        .route(
            "/api/v1/routing/filters/prefix-lists/{name}",
            delete(handlers::remove_prefix_list),
        )
        .route(
            "/api/v1/routing/filters/as-path",
            get(handlers::list_as_path_filters),
        )
        .route(
            "/api/v1/routing/filters/as-path",
            post(handlers::add_as_path_filter),
        )
        .route(
            "/api/v1/routing/filters/route-maps",
            get(handlers::list_route_maps),
        )
        .route(
            "/api/v1/routing/filters/route-maps",
            post(handlers::add_route_map_entry),
        )
        .route(
            "/api/v1/routing/filters/route-maps/{name}",
            get(handlers::get_route_map),
        )
        .route(
            "/api/v1/routing/filters/route-maps/{name}",
            delete(handlers::remove_route_map),
        )
        .route(
            "/api/v1/bridge-vlan",
            get(handlers::list_all_bridge_vlans),
        )
        .route(
            "/api/v1/bridge-vlan",
            post(handlers::add_bridge_vlan),
        )
        .route(
            "/api/v1/bridge-vlan/{bridge}",
            get(handlers::list_bridge_vlans),
        )
        .route(
            "/api/v1/bridge-vlan/{bridge}/{port}/{vlan}",
            delete(handlers::remove_bridge_vlan),
        )
        .route("/api/v1/vrf", get(handlers::list_vrfs))
        .route("/api/v1/vrf", post(handlers::create_vrf))
        .route("/api/v1/vrf/{name}", get(handlers::get_vrf))
        .route("/api/v1/vrf/{name}", delete(handlers::delete_vrf))
        .route(
            "/api/v1/vrf/{name}/interfaces",
            post(handlers::add_vrf_interface),
        )
        .route(
            "/api/v1/vrf/{name}/interfaces/{iface}",
            delete(handlers::remove_vrf_interface),
        )
        .route("/api/v1/l2tp/tunnels", get(handlers::list_l2tp_tunnels))
        .route("/api/v1/l2tp/tunnels", post(handlers::create_l2tp_tunnel))
        .route(
            "/api/v1/l2tp/tunnels/{name}",
            get(handlers::get_l2tp_tunnel),
        )
        .route(
            "/api/v1/l2tp/tunnels/{name}",
            delete(handlers::delete_l2tp_tunnel),
        )
        .route("/api/v1/l2tp/status", get(handlers::l2tp_status))
        .route("/api/v1/netwatch", get(handlers::list_netwatch))
        .route("/api/v1/netwatch", post(handlers::create_netwatch))
        .route("/api/v1/netwatch/{id}", get(handlers::get_netwatch))
        .route("/api/v1/netwatch/{id}", delete(handlers::delete_netwatch))
        .route(
            "/api/v1/netwatch/{id}/toggle",
            post(handlers::toggle_netwatch),
        )
        .route("/api/v1/netwatch/down", get(handlers::netwatch_down))
        .route(
            "/api/v1/bpf-qos/pcq",
            get(handlers::list_pcq_classes),
        )
        .route(
            "/api/v1/bpf-qos/pcq",
            post(handlers::add_pcq_class),
        )
        .route(
            "/api/v1/bpf-qos/pcq/{name}",
            delete(handlers::remove_pcq_class),
        )
        .route("/api/v1/snmp/config", get(handlers::get_snmp_config))
        .route(
            "/api/v1/snmp/config",
            put(handlers::update_snmp_config),
        )
        .route("/api/v1/snmp/mib", get(handlers::get_mib_entries))
        .route(
            "/api/v1/ipsec/status",
            get(handlers::ipsec_status),
        )
        .route(
            "/api/v1/ipsec/connect/{profile}",
            post(handlers::ipsec_connect),
        )
        .route(
            "/api/v1/ipsec/disconnect/{profile}",
            post(handlers::ipsec_disconnect),
        )
        .route("/api/v1/ntp/config", get(handlers::get_ntp_config))
        .route("/api/v1/ntp/config", put(handlers::set_ntp_config))
        .route("/api/v1/ntp/status", get(handlers::get_ntp_status))
        .route(
            "/api/v1/dns/doh",
            get(handlers::dns_doh_resolve),
        )
        .route(
            "/api/v1/tools/bandwidth-test",
            post(handlers::bandwidth_test),
        )
        .route(
            "/api/v1/graphs/{name}",
            get(handlers::get_graph_series),
        )
        .route(
            "/api/v1/graphs",
            get(handlers::list_graph_metrics),
        )
        .route(
            "/api/v1/graphs",
            post(handlers::add_graph_datapoint),
        )
        .route(
            "/api/v1/hotspot/sessions",
            get(handlers::hotspot_list_sessions),
        )
        .route(
            "/api/v1/hotspot/login",
            post(handlers::hotspot_login),
        )
        .route(
            "/api/v1/hotspot/logout/{id}",
            post(handlers::hotspot_logout),
        )
        .route(
            "/api/v1/hotspot/status",
            get(handlers::hotspot_status),
        )
        .route(
            "/api/v1/hotspot/walled-garden",
            get(handlers::hotspot_walled_garden),
        )
        .route(
            "/api/v1/bgp/inject",
            post(handlers::bgp_inject_route),
        )
        .route(
            "/api/v1/bgp/injected-routes",
            get(handlers::bgp_list_injected),
        )
        .route("/api/v1/ospf/spf-run", post(handlers::ospf_run_spf))
        .route(
            "/api/v1/ospf/lsdb",
            get(handlers::ospf_lsdb_status),
        )
        .route("/api/v1/lte/info", get(handlers::lte_info))
        .route("/api/v1/lte/refresh", post(handlers::lte_refresh))
        .route("/api/v1/lte/connect", post(handlers::lte_connect))
        .route(
            "/api/v1/lte/disconnect",
            post(handlers::lte_disconnect),
        )
        .route("/api/v1/lte/config", get(handlers::lte_config))
        .route(
            "/api/v1/lte/config",
            put(handlers::lte_set_config),
        )
        .route("/api/v1/ipv6/dhcp/pd", post(handlers::ipv6_dhcp_request_pd))
        .route("/api/v1/ipv6/radvd", get(handlers::ipv6_radvd_list))
        .route("/api/v1/ipv6/radvd", post(handlers::ipv6_radvd_add))
        .route(
            "/api/v1/ipv6/firewall",
            get(handlers::ipv6_firewall_list),
        )
        .route(
            "/api/v1/ipv6/firewall",
            post(handlers::ipv6_firewall_add),
        )
        .route("/api/v1/dhcp/relay", get(handlers::dhcp_relay_list))
        .route("/api/v1/dhcp/relay", post(handlers::dhcp_relay_add))
        .route(
            "/api/v1/dhcp/relay/{name}",
            delete(handlers::dhcp_relay_remove),
        )
        .route(
            "/api/v1/dhcp/snooping",
            get(handlers::dhcp_snooping_list),
        )
        .route(
            "/api/v1/dhcp/snooping",
            post(handlers::dhcp_snooping_set),
        )
        .route("/api/v1/bridge/igmp", get(handlers::igmp_list))
        .route("/api/v1/bridge/igmp", post(handlers::igmp_set_enabled))
        .route("/api/v1/bridge/stp", get(handlers::stp_list))
        .route("/api/v1/bridge/stp/{bridge}", get(handlers::stp_get))
        .route("/api/v1/bridge/stp", post(handlers::stp_set))
        .route("/api/v1/bridge/acl", get(handlers::bridge_acl_list))
        .route("/api/v1/bridge/acl", post(handlers::bridge_acl_add))
        .route(
            "/api/v1/bridge/acl/{idx}",
            delete(handlers::bridge_acl_remove),
        )
        .route("/api/v1/lldp/neighbors", get(handlers::lldp_neighbors))
        .route("/api/v1/routing/bfd", get(handlers::bfd_list))
        .route("/api/v1/routing/bfd", post(handlers::bfd_add))
        .route(
            "/api/v1/routing/bfd/{neighbor}",
            delete(handlers::bfd_remove),
        )
        .route(
            "/api/v1/routing/bfd/status/{neighbor}",
            get(handlers::bfd_status),
        )
        .route(
            "/api/v1/dns/static",
            get(handlers::dns_static_list),
        )
        .route(
            "/api/v1/dns/static",
            post(handlers::dns_static_add),
        )
        .route(
            "/api/v1/dns/static/{name}",
            delete(handlers::dns_static_remove),
        )
        .route("/api/v1/ntp/client", get(handlers::ntp_client_config))
        .route(
            "/api/v1/ntp/client",
            put(handlers::ntp_client_set_config),
        )
        .route(
            "/api/v1/ntp/client/sync",
            post(handlers::ntp_client_sync),
        )
        .route(
            "/api/v1/firewall/mangle",
            get(handlers::mangle_list),
        )
        .route(
            "/api/v1/firewall/mangle",
            post(handlers::mangle_add),
        )
        .route(
            "/api/v1/firewall/mangle/{idx}",
            delete(handlers::mangle_remove),
        )
        .route("/api/v1/routing/pbr", get(handlers::pbr_list))
        .route("/api/v1/routing/pbr", post(handlers::pbr_add))
        .route(
            "/api/v1/routing/pbr/{idx}",
            delete(handlers::pbr_remove),
        )
        .route("/api/v1/tunnel/eoip", get(handlers::eoip_list))
        .route("/api/v1/tunnel/eoip", post(handlers::eoip_create))
        .route(
            "/api/v1/tunnel/eoip/{name}",
            delete(handlers::eoip_delete),
        )
        .route("/api/v1/tunnel/gre", get(handlers::gre_list))
        .route("/api/v1/tunnel/gre", post(handlers::gre_create))
        .route(
            "/api/v1/tunnel/gre/{name}",
            delete(handlers::gre_delete),
        )
        .route(
            "/api/v1/traffic-flow/status",
            get(handlers::flow_status),
        )
        .route(
            "/api/v1/traffic-flow/records",
            get(handlers::flow_records),
        )
        .route(
            "/api/v1/traffic-flow/clear",
            post(handlers::flow_clear),
        )
        .route("/api/v1/tools/wol", get(handlers::wol_list))
        .route("/api/v1/tools/wol", post(handlers::wol_add))
        .route(
            "/api/v1/tools/wol/{name}",
            delete(handlers::wol_remove),
        )
        .route(
            "/api/v1/tools/wol/wake/{mac}",
            post(handlers::wol_wake),
        )
        .route("/api/v1/mpls/interfaces", get(handlers::mpls_interfaces))
        .route("/api/v1/mpls/interfaces", post(handlers::mpls_add_interface))
        .route("/api/v1/mpls/interfaces/{name}", delete(handlers::mpls_remove_interface))
        .route("/api/v1/mpls/lsps", get(handlers::mpls_lsps))
        .route("/api/v1/routing/rip/interfaces", get(handlers::rip_interfaces))
        .route("/api/v1/routing/rip/interfaces", post(handlers::rip_add_interface))
        .route("/api/v1/routing/rip/interfaces/{name}", delete(handlers::rip_remove_interface))
        .route("/api/v1/routing/rip/routes", get(handlers::rip_routes))
        .route("/api/v1/routing/ospfv3/areas", get(handlers::ospfv3_areas))
        .route("/api/v1/routing/ospfv3/areas", post(handlers::ospfv3_add_area))
        .route("/api/v1/routing/ospfv3/areas/{id}", delete(handlers::ospfv3_remove_area))
        .route("/api/v1/tools/traffic-gen", post(handlers::traffic_gen_start))
        .route("/api/v1/tools/sniffer", get(handlers::sniffer_status))
        .route("/api/v1/tools/sniffer", post(handlers::sniffer_set_enabled))
        .route("/api/v1/tools/sniffer/packets", get(handlers::sniffer_packets))
        .route("/api/v1/tools/sniffer/clear", post(handlers::sniffer_clear))
        .route("/api/v1/radius/coa/disconnect/{session}", post(handlers::radius_coa_disconnect))
        .route("/api/v1/backup/config", get(handlers::backup_config))
        .route("/api/v1/backup/config", put(handlers::backup_set_config))
        .route("/api/v1/backup/run", post(handlers::backup_run))
        .route("/api/v1/tools/email/config", get(handlers::email_config))
        .route("/api/v1/tools/email/config", put(handlers::email_set_config))
        .route("/api/v1/upnp/status", get(handlers::upnp_status))
        .route("/api/v1/upnp/enabled", post(handlers::upnp_set_enabled))
        .route("/api/v1/upnp/mappings", post(handlers::upnp_add_mapping))
        .route("/api/v1/upnp/mappings/{id}", delete(handlers::upnp_remove_mapping))
        .route("/api/v1/dot1x/ports", get(handlers::dot1x_ports))
        .route("/api/v1/dot1x/ports", post(handlers::dot1x_set_port))
        .route("/api/v1/dot1x/ports/{name}", delete(handlers::dot1x_remove_port))
        .route("/api/v1/cloud/ddns", get(handlers::ddns_config))
        .route("/api/v1/cloud/ddns", put(handlers::ddns_set_config))
        .route("/api/v1/cloud/ddns/update", post(handlers::ddns_update))
        .route("/api/v1/system/health", get(handlers::health_status))
        .route("/api/v1/system/health", post(handlers::health_update))
        .route("/api/v1/system/accounting", get(handlers::accounting_status))
        .route("/api/v1/system/accounting", post(handlers::accounting_set_enabled))
        .route("/api/v1/system/accounting/clear", post(handlers::accounting_clear))
        .route("/api/v1/firewall/layer7", get(handlers::layer7_list))
        .route("/api/v1/firewall/layer7", post(handlers::layer7_add))
        .route("/api/v1/firewall/layer7/{name}", get(handlers::layer7_get))
        .route("/api/v1/firewall/layer7/{name}", delete(handlers::layer7_remove))
        .route("/api/v1/firewall/layer7/{name}/toggle", post(handlers::layer7_toggle))
        .route("/api/v1/firewall/layer7/match", post(handlers::layer7_match))
        .route("/api/v1/ssh/config", get(handlers::ssh_config))
        .route("/api/v1/ssh/config", put(handlers::ssh_set_config))
        .route("/api/v1/ssh/restart", post(handlers::ssh_restart))
        .route("/api/v1/syslog/config", get(handlers::syslog_config))
        .route("/api/v1/syslog/config", put(handlers::syslog_set_config))
        .route("/api/v1/syslog/entries", get(handlers::syslog_entries))
        .route("/api/v1/syslog/clear", post(handlers::syslog_clear))
        .route("/api/v1/ipv6/dhcp-relay", get(handlers::dhcpv6_relay_list))
        .route("/api/v1/ipv6/dhcp-relay", post(handlers::dhcpv6_relay_add))
        .route("/api/v1/ipv6/dhcp-relay/{name}", delete(handlers::dhcpv6_relay_remove))
        .route("/api/v1/dns/dot", get(handlers::dns_dot_resolve))
        .route("/api/v1/net/proxy-arp", get(handlers::proxy_arp_list))
        .route("/api/v1/net/proxy-arp", post(handlers::proxy_arp_add))
        .route("/api/v1/net/proxy-arp/{idx}", delete(handlers::proxy_arp_remove))
        .route("/api/v1/bridge/isolation", get(handlers::bridge_isolation_list))
        .route("/api/v1/bridge/isolation", post(handlers::bridge_isolation_set))
        .route("/api/v1/bridge/igmp-proxy", get(handlers::igmp_proxy_config))
        .route("/api/v1/bridge/igmp-proxy", post(handlers::igmp_proxy_set_config))
        .route("/api/v1/qos/burst", get(handlers::burst_list))
        .route("/api/v1/qos/burst", post(handlers::burst_add))
        .route("/api/v1/qos/burst/{idx}", delete(handlers::burst_remove))
        .route("/api/v1/dhcp/radius", get(handlers::dhcp_radius_list))
        .route("/api/v1/dhcp/radius", post(handlers::dhcp_radius_add))
        .route("/api/v1/dhcp/radius/{idx}", delete(handlers::dhcp_radius_remove))
        .route("/api/v1/lldp/mndp", get(handlers::mndp_list))
        .route("/api/v1/system/upgrade", get(handlers::upgrade_config))
        .route("/api/v1/system/upgrade", put(handlers::upgrade_set_config))
        .route("/api/v1/system/upgrade/check", post(handlers::upgrade_check))
        .route("/api/v1/system/upgrade/run", post(handlers::upgrade_run))
        .route("/api/v1/system/watchdog", get(handlers::watchdog_config))
        .route("/api/v1/system/watchdog", put(handlers::watchdog_set_config))
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
