#![cfg(feature = "api")]

use crate::api::{AppState, err, json_bool, json_str_array, json_u64, ok};
use crate::traits::NetlinkNat;
use crate::wireguard;
use crate::{billing, routing};
use axum::{
    Json,
    extract::{Path, State},
};
use std::net::{IpAddr, Ipv4Addr};

// ─── Health ────────────────────────────────────────────

pub(crate) async fn health_check() -> Json<serde_json::Value> {
    ok()
}

// ─── Interfaces ────────────────────────────────────────

pub(crate) async fn list_interfaces(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.iface_mgr.list().await {
        Ok(ifaces) => Json(serde_json::json!(ifaces)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_interface(
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

pub(crate) async fn get_interface(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.get(&name).await {
        Ok(iface) => Json(serde_json::json!(iface)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn set_interface_up(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.set_up(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn set_interface_down(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.iface_mgr.set_down(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn set_interface_mtu(
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

// ─── Firewall ──────────────────────────────────────────

pub(crate) async fn list_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    let zones = ["lan", "wan", "vpn"];
    let mut all_rules = Vec::new();
    for zone in &zones {
        if let Ok(r) = s.fw_mgr.list_rules(zone).await {
            all_rules.extend(r);
        }
    }
    Json(serde_json::json!(all_rules))
}

pub(crate) async fn add_rule(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let action = match body["action"].as_str() {
        Some("accept") => crate::traits::FirewallAction::Accept,
        Some("drop") => crate::traits::FirewallAction::Drop,
        Some("reject") => crate::traits::FirewallAction::Reject,
        _ => crate::traits::FirewallAction::Drop,
    };
    let rule = crate::traits::FirewallRule {
        handle: 0,
        zone: body["zone"].as_str().unwrap_or("wan").to_string(),
        chain: body["chain"].as_str().unwrap_or("forward").to_string(),
        protocol: body["protocol"].as_str().map(|s| s.to_string()),
        src_addr: body["src_addr"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok()),
        dst_addr: body["dst_addr"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok()),
        src_port: body["src_port"].as_u64().map(|v| v as u16),
        dst_port: body["dst_port"].as_u64().map(|v| v as u16),
        action,
        position: 0,
    };
    match s.fw_mgr.add_rule(&rule).await {
        Ok(handle) => Json(serde_json::json!({"handle": handle})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_rule(
    State(s): State<AppState>,
    Path(handle): Path<u64>,
) -> Json<serde_json::Value> {
    match s.fw_mgr.delete_rule(handle).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn flush_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.fw_mgr.flush_rules().await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── NAT ──────────────────────────────────────────────

pub(crate) async fn list_nat_rules(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.nat_mgr.list_rules().await {
        Ok(rules) => Json(serde_json::json!(rules)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_nat_rule(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::traits::NatKind;
    let kind = match body["kind"].as_str() {
        Some("snat") => NatKind::Snat,
        Some("dnat") => NatKind::Dnat,
        Some("masquerade") => NatKind::Masquerade,
        _ => NatKind::Snat,
    };
    let rule = crate::traits::NatRule {
        handle: 0,
        iface: body["iface"].as_str().unwrap_or("eth0").to_string(),
        kind,
        src_addr: body["src_addr"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok()),
        dst_addr: body["dst_addr"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok()),
        to_addr: body["to_addr"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok()),
        to_port: body["to_port"].as_u64().map(|v| v as u16),
    };
    match s.nat_mgr.backend().add_rule(&rule).await {
        Ok(handle) => Json(serde_json::json!({"handle": handle})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_nat_rule(
    State(s): State<AppState>,
    Path(handle): Path<u64>,
) -> Json<serde_json::Value> {
    match s.nat_mgr.delete_rule(handle).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Routes ────────────────────────────────────────────

pub(crate) async fn list_routes(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.route_mgr.list_routes().await {
        Ok(routes) => Json(serde_json::json!(routes)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_route(
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

pub(crate) async fn delete_route(
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

// ─── QoS ──────────────────────────────────────────────

pub(crate) async fn attach_qdisc(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let kind = match body["kind"].as_str() {
        Some("htb") => crate::traits::QdiscKind::Htb,
        Some("fq_codel") => crate::traits::QdiscKind::FqCodel,
        Some("cake") => crate::traits::QdiscKind::Cake,
        _ => crate::traits::QdiscKind::Htb,
    };
    let config = crate::traits::QdiscConfig {
        kind,
        iface: body["iface"].as_str().unwrap_or("eth0").to_string(),
        handle: body["handle"].as_u64().unwrap_or(0x10) as u32,
        parent: body["parent"].as_u64().unwrap_or(0) as u32,
        rate: Some(body["rate"].as_u64().unwrap_or(100_000_000)),
        ceil: Some(body["ceil"].as_u64().unwrap_or(100_000_000)),
    };
    match s.qos_mgr.add_qdisc(&config).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_classes(State(_s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

pub(crate) async fn add_class(
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

pub(crate) async fn delete_class(
    State(s): State<AppState>,
    Path(classid): Path<u32>,
) -> Json<serde_json::Value> {
    match s.qos_mgr.delete_class("eth0", classid).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Conntrack ─────────────────────────────────────────

pub(crate) async fn get_conntrack_stats(State(s): State<AppState>) -> Json<serde_json::Value> {
    let ct = s.ct_mgr.lock().await;
    let count = ct.count().await.unwrap_or(0);
    let max = ct.max();
    Json(serde_json::json!({
        "count": count,
        "max": max,
        "usage_ratio": ct.usage_ratio(count),
    }))
}

pub(crate) async fn set_conntrack_max(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let max = body["max"].as_u64().unwrap_or(262_144) as u32;
    let mut ct = s.ct_mgr.lock().await;
    match ct.set_max(max).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_top_talkers(State(s): State<AppState>) -> Json<serde_json::Value> {
    let ct = s.ct_mgr.lock().await;
    match ct.top_talkers(20).await {
        Ok(talkers) => Json(serde_json::json!(talkers)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_protocol_distribution(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let ct = s.ct_mgr.lock().await;
    match ct.protocol_distribution().await {
        Ok(dist) => Json(serde_json::json!(dist)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Monitoring ───────────────────────────────────────

pub(crate) async fn get_bandwidth(State(s): State<AppState>) -> Json<serde_json::Value> {
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

pub(crate) async fn get_system_stats(State(s): State<AppState>) -> Json<serde_json::Value> {
    let (cpu, mem_total, mem_used, uptime_secs) = crate::api::monitoring::get_system_info();
    let ct = s.ct_mgr.lock().await;
    Json(serde_json::json!({
        "cpu_percent": cpu,
        "memory": { "total_mb": mem_total, "used_mb": mem_used },
        "uptime_secs": uptime_secs,
        "conntrack_count": ct.count().await.unwrap_or(0),
        "conntrack_max": ct.max(),
    }))
}

// ─── Users ─────────────────────────────────────────────

pub(crate) async fn list_users(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.user_mgr.list_users().await {
        Ok(users) => Json(serde_json::json!(users)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_user(
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
    if let Err(e) = user.validate() {
        return err(e);
    }
    match s.user_mgr.create_user(user).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn update_user(
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
    if let Err(e) = user.validate() {
        return err(e);
    }
    match s.user_mgr.update_user(&user).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_user(
    State(s): State<AppState>,
    Path(username): Path<String>,
) -> Json<serde_json::Value> {
    match s.user_mgr.delete_user(&username).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Packages ─────────────────────────────────────────

pub(crate) async fn list_packages(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.user_mgr.list_packages().await {
        Ok(packages) => Json(serde_json::json!(packages)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_package(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
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
        name: body["name"].as_str().unwrap_or("").to_string(),
        description: body["description"].as_str().unwrap_or("").to_string(),
        profiles,
        session_timeout: body["session_timeout"].as_u64().map(|v| v as u32),
    };
    if let Err(e) = pkg.validate() {
        return err(e);
    }
    match s.user_mgr.create_package(pkg).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn update_package(
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

pub(crate) async fn delete_package(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.user_mgr.delete_package(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Dynamic Routing ──────────────────────────────────

pub(crate) async fn list_bgp_peers(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.list_bgp_peers().await {
        Ok(peers) => Json(serde_json::json!(peers)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_bgp_peer(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let peer = routing::BgpPeer {
        neighbor_ip: body["neighbor_ip"].as_str().unwrap_or("").to_string(),
        remote_asn: json_u64(&body["remote_asn"]).unwrap_or(0) as u32,
        local_asn: json_u64(&body["local_asn"]).unwrap_or(0) as u32,
        multihop: json_bool(&body["multihop"]).unwrap_or(false),
        password: body["password"].as_str().map(|s| s.to_string()),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match s.routing_mgr.add_bgp_peer(&peer).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_bgp_peer(
    State(s): State<AppState>,
    Path(ip): Path<String>,
) -> Json<serde_json::Value> {
    match s.routing_mgr.remove_bgp_peer(&ip).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_bgp_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_bgp_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_ospf_areas(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.list_ospf_areas().await {
        Ok(areas) => Json(serde_json::json!(areas)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_ospf_area(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let area = routing::OspfArea {
        area_id: body["area_id"].as_str().unwrap_or("").to_string(),
        interfaces: json_str_array(&body["interfaces"]),
        networks: json_str_array(&body["networks"]),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
    };
    match s.routing_mgr.add_ospf_area(&area).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_ospf_area(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match s.routing_mgr.remove_ospf_area(&id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_ospf_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_ospf_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_dynamic_routes(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.routing_mgr.get_routing_table(None).await {
        Ok(routes) => Json(serde_json::json!(routes)),
        Err(e) => err(e.to_string()),
    }
}

// ─── WireGuard ─────────────────────────────────────────

pub(crate) async fn list_wg_interfaces(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.wg_mgr.list_interfaces().await {
        Ok(list) => Json(serde_json::json!(list)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_wg_interface(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let iface = wireguard::WireGuardInterface {
        name: body["name"].as_str().unwrap_or("").to_string(),
        private_key: body["private_key"].as_str().map(|s| s.to_string()),
        listen_port: json_u64(&body["listen_port"]).unwrap_or(51820) as u16,
        public_key: body["public_key"].as_str().unwrap_or("").to_string(),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
        mtu: json_u64(&body["mtu"]).unwrap_or(1420) as u16,
    };
    match s.wg_mgr.create_interface(&iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_wg_interface(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.wg_mgr.delete_interface(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_wg_peers(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.wg_mgr.list_peers(&name).await {
        Ok(peers) => Json(serde_json::json!(peers)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_wg_peer(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let peer = wireguard::WireGuardPeer {
        interface: name,
        public_key: body["public_key"].as_str().unwrap_or("").to_string(),
        allowed_ips: json_str_array(&body["allowed_ips"]),
        endpoint: body["endpoint"].as_str().map(|s| s.to_string()),
        endpoint_port: json_u64(&body["endpoint_port"]).map(|v| v as u16),
        persistent_keepalive: json_u64(&body["persistent_keepalive"]).map(|v| v as u16),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
    };
    match s.wg_mgr.add_peer(&peer).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_wg_peer(
    State(s): State<AppState>,
    Path((name, pubkey)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match s.wg_mgr.remove_peer(&name, &pubkey).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_wg_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.wg_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Billing ─────────────────────────────────────────

pub(crate) async fn list_billing_plans(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.billing_mgr.list_plans().await {
        Ok(plans) => Json(serde_json::json!(plans)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_billing_plan(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let plan = billing::BillingPlan {
        name: body["name"].as_str().unwrap_or("").to_string(),
        price_monthly: json_u64(&body["price_monthly"]).unwrap_or(0),
        price_setup: json_u64(&body["price_setup"]).unwrap_or(0),
        currency: body["currency"].as_str().unwrap_or("IDR").to_string(),
        grace_days: json_u64(&body["grace_days"]).unwrap_or(7) as u32,
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
    };
    match s.billing_mgr.create_plan(&plan).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_invoices(
    State(s): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let username = params.get("username").map(|s| s.as_str()).unwrap_or("");
    match s.billing_mgr.list_invoices(username).await {
        Ok(invoices) => Json(serde_json::json!(invoices)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn generate_invoice(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let invoice = billing::Invoice {
        id: body["id"].as_str().unwrap_or("INV-000").to_string(),
        username: body["username"].as_str().unwrap_or("").to_string(),
        amount: json_u64(&body["amount"]).unwrap_or(0),
        currency: body["currency"].as_str().unwrap_or("IDR").to_string(),
        issued_at: now,
        due_at: now + json_u64(&body["grace_days"]).unwrap_or(7) * 86400,
        paid_at: None,
        status: billing::InvoiceStatus::Pending,
        items: vec![],
    };
    match s.billing_mgr.generate_invoice(&invoice).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn mark_invoice_paid(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match s.billing_mgr.mark_invoice_paid(&id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_billing_summary(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.billing_mgr.get_billing_summary().await {
        Ok(summary) => Json(serde_json::json!(summary)),
        Err(e) => err(e.to_string()),
    }
}
