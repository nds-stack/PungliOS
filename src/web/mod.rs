#![cfg(feature = "web")]

use crate::api::AppState;
use axum::{Router, extract::State, response::Html, routing::get};
use std::net::IpAddr;
use std::sync::Arc;
use tera::{Context, Tera};

fn setup_tera() -> Tera {
    let template_path = if let Ok(exe) = std::env::current_exe() {
        let dir = exe.parent().unwrap_or(std::path::Path::new("."));
        let tmpl_dir = dir.join("templates");
        if tmpl_dir.is_dir() {
            tmpl_dir.join("**/*.html").to_string_lossy().to_string()
        } else if let Some(grandparent) = dir.parent() {
            let fallback = grandparent.join("templates");
            if fallback.is_dir() {
                fallback.join("**/*.html").to_string_lossy().to_string()
            } else {
                "templates/**/*.html".to_string()
            }
        } else {
            "templates/**/*.html".to_string()
        }
    } else {
        "templates/**/*.html".to_string()
    };
    Tera::new(&template_path).unwrap_or_else(|e| {
        tracing::error!("failed to load templates: {e}");
        std::process::exit(1);
    })
}

#[derive(Clone)]
pub struct WebState {
    pub tmpl: Arc<Tera>,
    pub app: AppState,
}

pub fn router(state: AppState) -> Router {
    let tera = setup_tera();
    let ws = WebState {
        tmpl: Arc::new(tera),
        app: state,
    };

    Router::new()
        .route("/", get(dashboard))
        .route("/web/interfaces", get(interfaces_page))
        .route("/web/firewall", get(firewall_page))
        .route("/web/nat", get(nat_page))
        .route("/web/routes", get(routes_page))
        .route("/web/qos", get(qos_page))
        .route("/web/users", get(users_page))
        .route("/web/packages", get(packages_page))
        .route("/web/sessions", get(sessions_page))
        .route("/web/dhcp", get(dhcp_page))
        .route("/web/dns", get(dns_page))
        .route("/web/monitoring", get(monitoring_page))
        .route("/web/routing/bgp", get(bgp_page))
        .route("/web/routing/ospf", get(ospf_page))
        .route("/web/routing/table", get(routing_table_page))
        .route("/web/wireguard", get(wireguard_page))
        .route("/web/billing", get(billing_page))
        .route("/web/failover", get(failover_page))
        .route("/web/vrrp", get(vrrp_page))
        .with_state(ws)
}

fn render(tmpl: &Tera, name: &str, ctx: &Context) -> Html<String> {
    match tmpl.render(name, ctx) {
        Ok(html) => Html(html),
        Err(e) => {
            tracing::error!("template '{name}' error: {e}");
            Html(format!(
                "<h1>500 Internal Error</h1><pre>template error: {e}</pre>"
            ))
        }
    }
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn addr_str(addr: &IpAddr) -> String {
    addr.to_string()
}

fn interface_vec(ctx: &mut Context, ifaces: &[crate::traits::Interface]) {
    let items: Vec<serde_json::Value> = ifaces
        .iter()
        .map(|i| {
            serde_json::json!({
                "name": i.name,
                "index": i.index,
                "mac": mac_str(&i.mac),
                "addresses": i.addresses.iter().map(addr_str).collect::<Vec<_>>(),
                "mtu": i.mtu,
                "up": i.up,
            })
        })
        .collect();
    ctx.insert("interfaces", &items);
}

fn rule_vec(rules: &[crate::traits::FirewallRule]) -> Vec<serde_json::Value> {
    rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "handle": r.handle,
                "zone": r.zone,
                "chain": r.chain,
                "protocol": r.protocol,
                "src_addr": r.src_addr.map(|a| addr_str(&a)),
                "dst_addr": r.dst_addr.map(|a| addr_str(&a)),
                "action": r.action,
            })
        })
        .collect()
}

fn nat_vec(rules: &[crate::traits::NatRule]) -> Vec<serde_json::Value> {
    rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "handle": r.handle,
                "iface": r.iface,
                "kind": r.kind,
                "src_addr": r.src_addr.map(|a| addr_str(&a)),
                "dst_addr": r.dst_addr.map(|a| addr_str(&a)),
                "to_addr": r.to_addr.map(|a| addr_str(&a)),
            })
        })
        .collect()
}

fn route_vec(routes: &[crate::traits::Route]) -> Vec<serde_json::Value> {
    routes
        .iter()
        .map(|r| {
            serde_json::json!({
                "destination": addr_str(&r.destination),
                "prefix": r.prefix,
                "nexthop": r.nexthop.map(|a| addr_str(&a)),
                "iface": r.iface,
                "metric": r.metric,
            })
        })
        .collect()
}

// ---- Handlers ----

async fn dashboard(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ifaces = ws.app.iface_mgr.list().await.unwrap_or_default();
    let zones = ["lan", "wan", "vpn"];
    let mut all_rules = Vec::new();
    for zone in &zones {
        if let Ok(r) = ws.app.fw_mgr.list_rules(zone).await {
            all_rules.extend(r);
        }
    }
    let users = ws.app.user_mgr.list_users().await.unwrap_or_default();
    ctx.insert("page", "dashboard");
    ctx.insert("page_title", "Dashboard");
    ctx.insert("iface_count", &ifaces.len());
    ctx.insert("rule_count", &all_rules.len());
    ctx.insert("user_count", &users.len());
    ctx.insert("session_count", &0usize);
    render(&ws.tmpl, "dashboard.html", &ctx)
}

async fn interfaces_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ifaces = ws.app.iface_mgr.list().await.unwrap_or_default();
    ctx.insert("page", "interfaces");
    ctx.insert("page_title", "Interfaces");
    interface_vec(&mut ctx, &ifaces);
    render(&ws.tmpl, "interfaces.html", &ctx)
}

async fn firewall_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let zones = ["lan", "wan", "vpn"];
    let mut all_rules = Vec::new();
    for zone in &zones {
        if let Ok(r) = ws.app.fw_mgr.list_rules(zone).await {
            all_rules.extend(r);
        }
    }
    ctx.insert("page", "firewall");
    ctx.insert("page_title", "Firewall");
    ctx.insert("rules", &rule_vec(&all_rules));
    render(&ws.tmpl, "firewall.html", &ctx)
}

async fn nat_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let rules = ws.app.nat_mgr.list_rules().await.unwrap_or_default();
    ctx.insert("page", "nat");
    ctx.insert("page_title", "NAT");
    ctx.insert("rules", &nat_vec(&rules));
    render(&ws.tmpl, "nat.html", &ctx)
}

async fn routes_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let routes = ws.app.route_mgr.list_routes().await.unwrap_or_default();
    ctx.insert("page", "routes");
    ctx.insert("page_title", "Routes");
    ctx.insert("routes", &route_vec(&routes));
    render(&ws.tmpl, "routes.html", &ctx)
}

async fn qos_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ifaces = ws.app.iface_mgr.list().await.unwrap_or_default();
    ctx.insert("page", "qos");
    ctx.insert("page_title", "QoS");
    interface_vec(&mut ctx, &ifaces);
    render(&ws.tmpl, "qos.html", &ctx)
}

async fn users_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let all_users = ws.app.user_mgr.list_users().await.unwrap_or_default();
    let packages = ws.app.user_mgr.list_packages().await.unwrap_or_default();
    let user_items: Vec<serde_json::Value> = all_users
        .iter()
        .map(|u| {
            serde_json::json!({
                "username": u.username,
                "enabled": u.enabled,
                "package_name": u.package_name,
                "ip_address": u.ip_address.map(|a| a.to_string()),
                "mac_address": u.mac_address,
                "notes": u.notes,
            })
        })
        .collect();
    ctx.insert("page", "users");
    ctx.insert("page_title", "Users");
    ctx.insert("users", &user_items);
    ctx.insert("packages", &packages);
    ctx.insert("user_count", &all_users.len());
    ctx.insert(
        "enabled_count",
        &all_users.iter().filter(|u| u.enabled).count(),
    );
    render(&ws.tmpl, "users.html", &ctx)
}

async fn packages_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let packages = ws.app.user_mgr.list_packages().await.unwrap_or_default();
    let pkg_items: Vec<serde_json::Value> = packages
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "description": p.description,
                "profiles": p.profiles,
                "session_timeout": p.session_timeout,
            })
        })
        .collect();
    ctx.insert("page", "packages");
    ctx.insert("page_title", "Packages");
    ctx.insert("packages", &pkg_items);
    render(&ws.tmpl, "packages.html", &ctx)
}

async fn sessions_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let users = ws.app.user_mgr.list_users().await.unwrap_or_default();
    let session_items: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            serde_json::json!({
                "username": u.username,
                "enabled": u.enabled,
                "ip_address": u.ip_address.map(|a| a.to_string()),
            })
        })
        .collect();
    ctx.insert("page", "sessions");
    ctx.insert("page_title", "PPPoE Sessions");
    ctx.insert("sessions", &session_items);
    render(&ws.tmpl, "sessions.html", &ctx)
}

async fn dhcp_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ifaces = ws.app.iface_mgr.list().await.unwrap_or_default();
    ctx.insert("page", "dhcp");
    ctx.insert("page_title", "DHCP Server");
    interface_vec(&mut ctx, &ifaces);
    render(&ws.tmpl, "dhcp.html", &ctx)
}

async fn dns_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    ctx.insert("page", "dns");
    ctx.insert("page_title", "DNS Forwarder");
    render(&ws.tmpl, "dns.html", &ctx)
}

async fn monitoring_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ct_count = ws.app.ct_mgr.lock().await.count().await.unwrap_or(0);
    ctx.insert("page", "monitoring");
    ctx.insert("page_title", "Monitoring");
    ctx.insert("conntrack_count", &ct_count);
    render(&ws.tmpl, "monitoring.html", &ctx)
}

async fn bgp_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let peers = ws
        .app
        .routing_mgr
        .list_bgp_peers()
        .await
        .unwrap_or_default();
    let status = ws.app.routing_mgr.get_bgp_status().await.ok();
    let peer_items: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "neighbor_ip": p.neighbor_ip,
                "remote_asn": p.remote_asn,
                "local_asn": p.local_asn,
                "multihop": p.multihop,
                "enabled": p.enabled,
                "description": p.description,
            })
        })
        .collect();
    ctx.insert("page", "bgp");
    ctx.insert("page_title", "BGP Routing");
    ctx.insert("peers", &peer_items);
    ctx.insert("bgp_status", &status);
    render(&ws.tmpl, "bgp.html", &ctx)
}

async fn ospf_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let areas = ws
        .app
        .routing_mgr
        .list_ospf_areas()
        .await
        .unwrap_or_default();
    let status = ws.app.routing_mgr.get_ospf_status().await.ok();
    let area_items: Vec<serde_json::Value> = areas
        .iter()
        .map(|a| {
            serde_json::json!({
                "area_id": a.area_id,
                "interfaces": a.interfaces,
                "networks": a.networks,
                "enabled": a.enabled,
            })
        })
        .collect();
    ctx.insert("page", "ospf");
    ctx.insert("page_title", "OSPF Routing");
    ctx.insert("areas", &area_items);
    ctx.insert("ospf_status", &status);
    render(&ws.tmpl, "ospf.html", &ctx)
}

async fn routing_table_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let routes = ws
        .app
        .routing_mgr
        .get_routing_table(None)
        .await
        .unwrap_or_default();
    ctx.insert("page", "routing-table");
    ctx.insert("page_title", "Routing Table");
    ctx.insert("routes", &routes);
    render(&ws.tmpl, "routing_table.html", &ctx)
}

async fn wireguard_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let ifaces = ws.app.wg_mgr.list_interfaces().await.unwrap_or_default();
    let status = ws.app.wg_mgr.get_status().await.ok();
    let mut iface_items: Vec<serde_json::Value> = Vec::new();

    for i in &ifaces {
        let peers = ws.app.wg_mgr.list_peers(&i.name).await.unwrap_or_default();
        let peer_items: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "public_key": p.public_key,
                    "allowed_ips": p.allowed_ips,
                    "endpoint": p.endpoint,
                    "endpoint_port": p.endpoint_port,
                    "persistent_keepalive": p.persistent_keepalive,
                    "enabled": p.enabled,
                })
            })
            .collect();
        iface_items.push(serde_json::json!({
            "name": i.name,
            "listen_port": i.listen_port,
            "public_key": i.public_key,
            "enabled": i.enabled,
            "mtu": i.mtu,
            "peers": peer_items,
        }));
    }

    ctx.insert("page", "wireguard");
    ctx.insert("page_title", "WireGuard VPN");
    ctx.insert("interfaces", &iface_items);
    ctx.insert("wg_status", &status);
    render(&ws.tmpl, "wireguard.html", &ctx)
}

async fn billing_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let plans = ws.app.billing_mgr.list_plans().await.unwrap_or_default();
    let summary = ws.app.billing_mgr.get_billing_summary().await.ok();
    ctx.insert("page", "billing");
    ctx.insert("page_title", "Billing");
    ctx.insert("plans", &plans);
    ctx.insert("billing_summary", &summary);
    render(&ws.tmpl, "billing.html", &ctx)
}

async fn failover_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let uplinks = ws.app.failover_mgr.list_uplinks().await.unwrap_or_default();
    let status = ws.app.failover_mgr.get_status().await.ok();
    ctx.insert("page", "failover");
    ctx.insert("page_title", "PPPoE Failover");
    ctx.insert("uplinks", &uplinks);
    ctx.insert("failover_status", &status);
    render(&ws.tmpl, "failover.html", &ctx)
}

async fn vrrp_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let instances = ws.app.vrrp_mgr.list_instances().await.unwrap_or_default();
    let status = ws.app.vrrp_mgr.get_status().await.ok();
    ctx.insert("page", "vrrp");
    ctx.insert("page_title", "VRRP");
    ctx.insert("instances", &instances);
    ctx.insert("vrrp_status", &status);
    render(&ws.tmpl, "vrrp.html", &ctx)
}
