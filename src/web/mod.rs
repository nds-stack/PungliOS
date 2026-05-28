#![cfg(feature = "web")]

use crate::api::AppState;
use axum::{Router, extract::State, response::Html, routing::get};
use std::net::IpAddr;
use std::sync::Arc;
use tera::{Context, Tera};

fn setup_tera() -> Tera {
    let template_path = if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join("templates").join("**/*.html");
            path.to_string_lossy().to_string()
        } else {
            "templates/**/*.html".to_string()
        }
    } else {
        "templates/**/*.html".to_string()
    };
    Tera::new(&template_path).expect("failed to load templates")
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
        .with_state(ws)
}

fn render(tmpl: &Tera, name: &str, ctx: &Context) -> Html<String> {
    Html(
        tmpl.render(name, ctx)
            .unwrap_or_else(|e| format!("<h1>Template error</h1><pre>{}</pre>", e)),
    )
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
    ctx.insert("page", "qos");
    ctx.insert("page_title", "QoS");
    ctx.insert("classes", &[] as &[serde_json::Value]);
    render(&ws.tmpl, "qos.html", &ctx)
}

async fn users_page(State(ws): State<WebState>) -> Html<String> {
    let mut ctx = Context::new();
    let users = ws.app.user_mgr.list_users().await.unwrap_or_default();
    let packages = ws.app.user_mgr.list_packages().await.unwrap_or_default();
    let user_items: Vec<serde_json::Value> = users
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
