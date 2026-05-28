#![cfg(feature = "api")]

use crate::traits::MockBackend;
use crate::traits::NetlinkNat;
use crate::{conntrack, firewall, net, qos, routing, user};
use axum::{
    Json, Router,
    extract::{Path, State},
    response::sse::{Event, Sse},
    routing::{delete, get, post, put},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

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
            monitoring_tx,
        }
    }

    pub fn start_monitoring(&self) {
        let app = self.clone();
        let tx = self.monitoring_tx.clone();
        tokio::spawn(async move {
            monitoring_loop(app, tx).await;
        });
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/interfaces", get(list_interfaces))
        .route("/api/v1/interfaces", post(create_interface))
        .route("/api/v1/interfaces/{name}", get(get_interface))
        .route("/api/v1/interfaces/{name}/up", post(set_interface_up))
        .route("/api/v1/interfaces/{name}/down", post(set_interface_down))
        .route("/api/v1/interfaces/{name}/mtu", put(set_interface_mtu))
        .route("/api/v1/firewall/rules", get(list_rules))
        .route("/api/v1/firewall/rules", post(add_rule))
        .route("/api/v1/firewall/rules/{handle}", delete(delete_rule))
        .route("/api/v1/firewall/flush", post(flush_rules))
        .route("/api/v1/nat/rules", get(list_nat_rules))
        .route("/api/v1/nat/rules", post(add_nat_rule))
        .route("/api/v1/nat/rules/{handle}", delete(delete_nat_rule))
        .route("/api/v1/routes", get(list_routes))
        .route("/api/v1/routes", post(add_route))
        .route("/api/v1/routes/del", post(delete_route))
        .route("/api/v1/qos/attach", post(attach_qdisc))
        .route("/api/v1/qos/classes", get(list_classes))
        .route("/api/v1/qos/classes", post(add_class))
        .route("/api/v1/qos/classes/{classid}", delete(delete_class))
        .route("/api/v1/conntrack/stats", get(get_conntrack_stats))
        .route("/api/v1/conntrack/max", put(set_conntrack_max))
        .route("/api/v1/routing/bgp/peers", get(list_bgp_peers))
        .route("/api/v1/routing/bgp/peers", post(add_bgp_peer))
        .route("/api/v1/routing/bgp/peers/{ip}", delete(remove_bgp_peer))
        .route("/api/v1/routing/bgp/status", get(get_bgp_status))
        .route("/api/v1/routing/ospf/areas", get(list_ospf_areas))
        .route("/api/v1/routing/ospf/areas", post(add_ospf_area))
        .route("/api/v1/routing/ospf/areas/{id}", delete(remove_ospf_area))
        .route("/api/v1/routing/ospf/status", get(get_ospf_status))
        .route("/api/v1/routing/table", get(list_dynamic_routes))
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/users", post(create_user))
        .route("/api/v1/users/{username}", put(update_user))
        .route("/api/v1/users/{username}", delete(delete_user))
        .route("/api/v1/packages", get(list_packages))
        .route("/api/v1/packages", post(create_package))
        .route("/api/v1/packages/{name}", put(update_package))
        .route("/api/v1/packages/{name}", delete(delete_package))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/monitoring/bandwidth", get(get_bandwidth))
        .route("/api/v1/monitoring/system", get(get_system_stats))
        .route("/api/v1/monitoring/stream", get(monitoring_stream))
        .with_state(state)
}

// ─── Handlers ────────────────────────────────────────

fn ok() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

fn err(msg: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({"error": msg}))
}

async fn health_check() -> Json<serde_json::Value> {
    ok()
}

async fn create_interface(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty()
        || name.len() > 15
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || "_.-:".contains(c))
    {
        return err("invalid interface name: must be 1-15 chars, alphanumeric with _-.:".into());
    }
    let config = crate::traits::InterfaceConfig {
        name,
        mtu: body["mtu"].as_u64().map(|v| v as u16),
        addresses: vec![],
        vlan_id: body["vlan_id"].as_u64().map(|v| v as u16),
        bridge: body["bridge"].as_str().map(|v| v.to_string()),
    };
    match s.iface_mgr.create(&config).await {
        Ok(iface) => Json(serde_json::json!(iface)),
        Err(e) => err(e.to_string()),
    }
}

async fn list_interfaces(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.iface_mgr.list().await {
        Ok(ifaces) => Json(serde_json::json!(ifaces)),
        Err(e) => err(e.to_string()),
    }
}

async fn get_interface(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.get(&name).await {
        Ok(iface) => Json(serde_json::json!(iface)),
        Err(e) => err(e.to_string()),
    }
}

async fn set_interface_up(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.set_up(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn set_interface_down(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.set_down(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn set_interface_mtu(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mtu = body["mtu"].as_u64().unwrap_or(1500) as u16;
    match s.iface_mgr.set_mtu(&name, mtu).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn list_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    let zones = ["lan", "wan", "vpn"];
    let mut all_rules = Vec::new();
    for zone in &zones {
        if let Ok(r) = s.fw_mgr.list_rules(zone).await {
            all_rules.extend(r);
        }
    }
    Json(serde_json::json!(all_rules))
}

async fn add_rule(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let zone = body["zone"].as_str().unwrap_or("lan");
    let chain = body["chain"].as_str().unwrap_or("forward");
    let action_str = body["action"].as_str().unwrap_or("accept");
    let action = match action_str {
        "drop" | "block" => crate::traits::FirewallAction::Drop,
        "reject" => crate::traits::FirewallAction::Reject,
        _ => crate::traits::FirewallAction::Accept,
    };
    let rule = crate::traits::FirewallRule {
        handle: 0,
        zone: zone.to_string(),
        chain: chain.to_string(),
        protocol: body["protocol"].as_str().map(|s| s.to_string()),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: body["dst_port"].as_u64().map(|p| p as u16),
        action,
        position: 0,
    };
    match s.fw_mgr.add_rule(&rule).await {
        Ok(h) => Json(serde_json::json!({"status": "ok", "handle": h})),
        Err(e) => err(e.to_string()),
    }
}

async fn delete_rule(
    State(s): State<AppState>,
    Path(handle): Path<u64>,
) -> Json<serde_json::Value> {
    match s.fw_mgr.delete_rule(handle).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn flush_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.fw_mgr.flush_rules().await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn list_nat_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.nat_mgr.list_rules().await {
        Ok(rules) => Json(serde_json::json!(rules)),
        Err(e) => err(e.to_string()),
    }
}

async fn add_nat_rule(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let kind_str = body["kind"].as_str().unwrap_or("masquerade");
    let kind = match kind_str {
        "snat" => crate::traits::NatKind::Snat,
        "dnat" => crate::traits::NatKind::Dnat,
        _ => crate::traits::NatKind::Masquerade,
    };
    let to = body["to_addr"]
        .as_str()
        .and_then(|a| a.parse::<Ipv4Addr>().ok())
        .map(IpAddr::V4);
    let rule = crate::traits::NatRule {
        handle: 0,
        iface: body["iface"].as_str().unwrap_or("eth0").to_string(),
        kind,
        src_addr: None,
        dst_addr: None,
        to_addr: to,
        to_port: None,
    };
    match s.nat_mgr.backend().add_rule(&rule).await {
        Ok(h) => Json(serde_json::json!({"status": "ok", "handle": h})),
        Err(e) => err(e.to_string()),
    }
}

async fn delete_nat_rule(
    State(s): State<AppState>,
    Path(handle): Path<u64>,
) -> Json<serde_json::Value> {
    match s.nat_mgr.delete_rule(handle).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn list_routes(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.route_mgr.list_routes().await {
        Ok(routes) => Json(serde_json::json!(routes)),
        Err(e) => err(e.to_string()),
    }
}

async fn add_route(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let dst_str = body["destination"].as_str().unwrap_or("0.0.0.0");
    let prefix = body["prefix"].as_u64().unwrap_or(24) as u8;
    let dest = dst_str.parse::<Ipv4Addr>().map(IpAddr::V4);
    match dest {
        Ok(dst) => {
            let nh = body["nexthop"]
                .as_str()
                .and_then(|n| n.parse::<Ipv4Addr>().ok())
                .map(IpAddr::V4);
            let route = crate::traits::Route {
                destination: dst,
                prefix,
                nexthop: nh,
                iface: body["iface"].as_str().map(|s| s.to_string()),
                metric: body["metric"].as_u64().map(|m| m as u32),
            };
            match s.route_mgr.add_route(&route).await {
                Ok(_) => ok(),
                Err(e) => err(e.to_string()),
            }
        }
        Err(e) => err(format!("invalid destination: {e}")),
    }
}

// ─── Monitoring ───────────────────────────────────────

async fn get_bandwidth(State(s): State<AppState>) -> Json<serde_json::Value> {
    let mut ifaces = Vec::new();
    if let Ok(list) = s.iface_mgr.list().await {
        for iface in &list {
            let _stats =
                metrics::gauge!("punglios.bandwidth.bytes", "interface" => iface.name.clone());
            ifaces.push(serde_json::json!({
                "name": iface.name,
                "mtu": iface.mtu,
                "up": iface.up,
                "rx_bytes": 0u64,
                "tx_bytes": 0u64,
            }));
        }
    }
    Json(serde_json::json!({"interfaces": ifaces}))
}

async fn get_system_stats(State(s): State<AppState>) -> Json<serde_json::Value> {
    let (cpu, mem_total, mem_used, uptime_secs) = get_system_info();
    Json(serde_json::json!({
        "cpu_percent": cpu,
        "memory": { "total_mb": mem_total, "used_mb": mem_used },
        "uptime_secs": uptime_secs,
        "conntrack_count": s.ct_mgr.lock().await.count().await.unwrap_or(0),
        "conntrack_max": s.ct_mgr.lock().await.max(),
    }))
}

fn get_system_info() -> (f64, u64, u64, u64) {
    let mut uptime = 0u64;
    let mut mem_total = 0u64;
    let mut mem_used = 0u64;
    let mut cpu = 0.0_f64;

    if cfg!(target_os = "linux") {
        uptime = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0) as u64;

        let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        mem_total = meminfo
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0);
        let mem_avail = meminfo
            .lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0);
        mem_used = mem_total.saturating_sub(mem_avail);

        cpu = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| {
                let line = s.lines().next()?;
                let parts: Vec<&str> = line.split_whitespace().collect();
                let total: u64 = parts[1..]
                    .iter()
                    .filter_map(|p| p.parse::<u64>().ok())
                    .sum();
                let idle: u64 = parts[4].parse().ok()?;
                Some(100.0 * (1.0 - idle as f64 / total as f64))
            })
            .unwrap_or(0.0);
    }

    (cpu, mem_total, mem_used, uptime)
}

async fn delete_route(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let dst_str = body["destination"].as_str().unwrap_or("0.0.0.0");
    let prefix = body["prefix"].as_u64().unwrap_or(24) as u8;
    let dest = dst_str.parse::<Ipv4Addr>().map(IpAddr::V4);
    match dest {
        Ok(dst) => match s.route_mgr.delete_route(dst, prefix).await {
            Ok(_) => ok(),
            Err(e) => err(e.to_string()),
        },
        Err(e) => err(format!("invalid destination: {e}")),
    }
}

async fn attach_qdisc(State(s): State<AppState>) -> Json<serde_json::Value> {
    let config = crate::traits::QdiscConfig {
        kind: crate::traits::QdiscKind::Htb,
        iface: "eth0".into(),
        handle: 0x10,
        parent: 0,
        rate: Some(1_000_000_000),
        ceil: Some(1_000_000_000),
    };
    match s.qos_mgr.add_qdisc(&config).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn list_classes(State(_s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

async fn add_class(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let config = crate::traits::ClassConfig {
        iface: body["iface"].as_str().unwrap_or("eth0").to_string(),
        classid: body["classid"].as_u64().unwrap_or(0x10_01) as u32,
        parent: body["parent"].as_u64().unwrap_or(0x10) as u32,
        rate: body["rate"].as_u64().unwrap_or(10_000_000),
        ceil: body["ceil"].as_u64().unwrap_or(10_000_000),
        burst: body["burst"].as_u64(),
        cburst: body["cburst"].as_u64(),
        priority: body["priority"].as_u64().unwrap_or(3) as u8,
    };
    match s.qos_mgr.add_class(&config).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn delete_class(
    State(s): State<AppState>,
    Path(classid): Path<u32>,
) -> Json<serde_json::Value> {
    match s.qos_mgr.delete_class("eth0", classid).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn get_conntrack_stats(State(s): State<AppState>) -> Json<serde_json::Value> {
    let ct = s.ct_mgr.lock().await;
    let count = ct.count().await.unwrap_or(0);
    let max = ct.max();
    Json(
        serde_json::json!({"count": count, "max": max, "usage_ratio": if max > 0 { count as f64 / max as f64 } else { 0.0 }}),
    )
}

async fn set_conntrack_max(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let max = body["max"].as_u64().unwrap_or(262144) as u32;
    let mut ct = s.ct_mgr.lock().await;
    match ct.set_max(max).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Dynamic Routing ──────────────────────────────────

async fn list_bgp_peers(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.list_bgp_peers().await {
        Ok(peers) => Json(serde_json::json!(peers)),
        Err(e) => err(e.to_string()),
    }
}

async fn add_bgp_peer(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let peer = routing::BgpPeer {
        neighbor_ip: body["neighbor_ip"].as_str().unwrap_or("").to_string(),
        remote_asn: body["remote_asn"].as_u64().unwrap_or(0) as u32,
        local_asn: body["local_asn"].as_u64().unwrap_or(0) as u32,
        multihop: body["multihop"].as_bool().unwrap_or(false),
        password: body["password"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match s.routing_mgr.add_bgp_peer(&peer).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn remove_bgp_peer(
    State(s): State<AppState>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    match s.routing_mgr.remove_bgp_peer(&ip).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn get_bgp_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_bgp_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

async fn list_ospf_areas(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.list_ospf_areas().await {
        Ok(areas) => Json(serde_json::json!(areas)),
        Err(e) => err(e.to_string()),
    }
}

async fn add_ospf_area(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let area = routing::OspfArea {
        area_id: body["area_id"].as_str().unwrap_or("").to_string(),
        interfaces: body["interfaces"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        networks: body["networks"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.routing_mgr.add_ospf_area(&area).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn remove_ospf_area(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match s.routing_mgr.remove_ospf_area(&id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn get_ospf_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_ospf_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

async fn list_dynamic_routes(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_routing_table(None).await {
        Ok(routes) => Json(serde_json::json!(routes)),
        Err(e) => err(e.to_string()),
    }
}

async fn list_users(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.user_mgr.list_users().await {
        Ok(users) => Json(serde_json::json!(users)),
        Err(e) => err(e.to_string()),
    }
}

async fn create_user(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let username = body["username"].as_str().unwrap_or("user").to_string();
    let mut user = crate::user::types::User {
        username,
        password_hash: String::new(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        package_name: body["package_name"].as_str().map(|s| s.to_string()),
        ip_address: body["ip_address"]
            .as_str()
            .and_then(|s| s.parse::<Ipv4Addr>().ok()),
        mac_address: body["mac_address"].as_str().map(|s| s.to_string()),
        notes: body["notes"].as_str().map(|s| s.to_string()),
    };
    if let Some(p) = body["password"].as_str() {
        user.set_password(p);
    }
    match s.user_mgr.create_user(user).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn update_user(
    State(s): State<AppState>,
    Path(username): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut user = match s.user_mgr.get_user(&username).await {
        Ok(u) => u,
        Err(e) => return err(e.to_string()),
    };
    if let Some(p) = body["password"].as_str() {
        user.set_password(p);
    }
    if let Some(e) = body["enabled"].as_bool() {
        user.enabled = e;
    }
    if let Some(p) = body["package_name"].as_str() {
        user.package_name = Some(p.to_string());
    }
    match s.user_mgr.update_user(&user).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn delete_user(
    State(s): State<AppState>,
    Path(username): Path<String>,
) -> Json<serde_json::Value> {
    match s.user_mgr.delete_user(&username).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn list_packages(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.user_mgr.list_packages().await {
        Ok(pkgs) => Json(serde_json::json!(pkgs)),
        Err(e) => err(e.to_string()),
    }
}

async fn create_package(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("pkg").to_string();
    let profiles: Vec<crate::user::types::BandwidthProfile> = body["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(crate::user::types::BandwidthProfile {
                        name: v["name"].as_str()?.to_string(),
                        upload_rate: v["upload_rate"].as_u64()?,
                        download_rate: v["download_rate"].as_u64()?,
                        upload_burst: v["upload_burst"].as_u64(),
                        download_burst: v["download_burst"].as_u64(),
                        priority: v["priority"].as_u64().unwrap_or(3) as u8,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let pkg = crate::user::types::UserPackage {
        name,
        description: body["description"].as_str().unwrap_or("").to_string(),
        profiles,
        session_timeout: body["session_timeout"].as_u64().map(|v| v as u32),
    };
    match s.user_mgr.create_package(pkg).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn delete_package(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.user_mgr.delete_package(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

async fn update_package(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let pkg = match s.user_mgr.get_package(&name).await {
        Ok(p) => p,
        Err(e) => return err(e.to_string()),
    };
    let profiles: Vec<crate::user::types::BandwidthProfile> = body["profiles"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(crate::user::types::BandwidthProfile {
                        name: v["name"].as_str()?.to_string(),
                        upload_rate: v["upload_rate"].as_u64()?,
                        download_rate: v["download_rate"].as_u64()?,
                        upload_burst: v["upload_burst"].as_u64(),
                        download_burst: v["download_burst"].as_u64(),
                        priority: v["priority"].as_u64().unwrap_or(3) as u8,
                    })
                })
                .collect()
        })
        .unwrap_or(pkg.profiles);
    let updated = crate::user::types::UserPackage {
        name,
        description: body["description"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or(pkg.description),
        profiles,
        session_timeout: body["session_timeout"]
            .as_u64()
            .map(|v| v as u32)
            .or(pkg.session_timeout),
    };
    match s.user_mgr.update_package(&updated).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── SSE Monitoring Stream ─────────────────────────────

async fn collect_monitoring_data(s: &AppState) -> serde_json::Value {
    let (cpu, mem_total, mem_used, uptime_secs) = get_system_info();
    let mut ifaces = Vec::new();
    if let Ok(list) = s.iface_mgr.list().await {
        for iface in &list {
            ifaces.push(serde_json::json!({
                "name": iface.name,
                "mtu": iface.mtu,
                "up": iface.up,
            }));
        }
    }
    let ct = s.ct_mgr.lock().await;
    let conntrack_count = ct.count().await.unwrap_or(0);
    let conntrack_max = ct.max();
    serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "cpu_percent": cpu,
        "memory": { "total_mb": mem_total, "used_mb": mem_used },
        "uptime_secs": uptime_secs,
        "conntrack": { "count": conntrack_count, "max": conntrack_max },
        "interfaces": ifaces,
        "users": s.user_mgr.user_count().await.unwrap_or(0),
    })
}

async fn monitoring_loop(app: AppState, tx: broadcast::Sender<String>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let data = collect_monitoring_data(&app).await;
        let msg = data.to_string();
        let _ = tx.send(msg);
    }
}

async fn monitoring_stream(
    State(s): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = s.monitoring_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(msg) => Some(Ok(Event::default().data(msg))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}
