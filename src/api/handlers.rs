#![cfg(feature = "api")]

use crate::api::{AppState, err, json_bool, json_str_array, json_u64, ok};
use crate::traits::NetlinkNat;
use crate::wireguard;
use crate::{billing, bpf_qos, pppoe, routing, tenancy, vrrp};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Deserialize)]
pub(crate) struct ToolsPingParams {
    pub target: String,
    pub count: Option<u32>,
    pub timeout: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct ToolsTraceParams {
    pub target: String,
    pub max_ttl: Option<u32>,
    pub timeout: Option<u64>,
}

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
        kind: None,
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
        Err(e) => err(e.to_string()),
    }
}

// ─── Bonding ───────────────────────────────────────────

pub(crate) async fn list_bonds(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.bond_mgr.list_bonds().await {
        Ok(bonds) => Json(serde_json::json!(bonds)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_bond(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.bond_mgr.get_bond(&name).await {
        Ok(bond) => Json(serde_json::json!(bond)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_bond(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("bond name is required".into());
    }
    let mode_str = body["mode"].as_str().unwrap_or("active-backup");
    let mode = crate::bonding::BondMode::from_str(mode_str).unwrap_or(crate::bonding::BondMode::ActiveBackup);
    let slaves: Vec<String> = body["slaves"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let bond = crate::bonding::BondInterface {
        name,
        mode,
        slaves,
        mtu: body["mtu"].as_u64().unwrap_or(1500) as u16,
        lacp_rate: None,
        min_links: body["min_links"].as_u64().map(|v| v as u32),
        miimon: body["miimon"].as_u64().map(|v| v as u32).or(Some(100)),
        updelay: body["updelay"].as_u64().map(|v| v as u32),
        downdelay: body["downdelay"].as_u64().map(|v| v as u32),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        addresses: vec![],
    };
    match s.bond_mgr.create_bond(&bond).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_bond(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.bond_mgr.delete_bond(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_bond_slave(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let slave = body["slave"].as_str().unwrap_or("").to_string();
    if slave.is_empty() {
        return err("slave name is required".into());
    }
    match s.bond_mgr.add_slave(&name, &slave).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_bond_slave(
    State(s): State<AppState>,
    Path((name, slave)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match s.bond_mgr.remove_slave(&name, &slave).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bond_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.bond_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Route Filters ─────────────────────────────────────

pub(crate) async fn list_prefix_lists(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let names = s.route_filter_mgr.list_prefix_lists();
    let mut result = Vec::new();
    for name in &names {
        let entries = s.route_filter_mgr.get_prefix_list(name);
        result.push(serde_json::json!({
            "name": name,
            "entries": entries,
        }));
    }
    Json(serde_json::json!(result))
}

pub(crate) async fn add_prefix_list_entry(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::routing::{PrefixListAction, PrefixListEntry};
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("prefix list name is required".into());
    }
    let action = match body["action"].as_str().unwrap_or("permit") {
        "deny" => PrefixListAction::Deny,
        _ => PrefixListAction::Permit,
    };
    let entry = PrefixListEntry {
        name: name.clone(),
        seq: body["seq"].as_u64().unwrap_or(10) as u32,
        action,
        prefix: body["prefix"].as_str().unwrap_or("0.0.0.0/0").to_string(),
        ge: body["ge"].as_u64().map(|v| v as u8),
        le: body["le"].as_u64().map(|v| v as u8),
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match s.route_filter_mgr.add_prefix_list_entry(entry) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_prefix_list(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let entries = s.route_filter_mgr.get_prefix_list(&name);
    Json(serde_json::json!(entries))
}

pub(crate) async fn remove_prefix_list(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.route_filter_mgr.remove_prefix_list(&name) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_as_path_filters(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let filters = s.route_filter_mgr.list_as_path_filters();
    Json(serde_json::json!(filters))
}

pub(crate) async fn add_as_path_filter(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::routing::{AsPathFilter, AsPathMatch, PrefixListAction};
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("AS path filter name is required".into());
    }
    let match_type = match body["match"].as_str().unwrap_or("any") {
        "exact" => {
            let path: Vec<u32> = body["as_path"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
                .unwrap_or_default();
            AsPathMatch::Exact(path)
        }
        _ => AsPathMatch::Any,
    };
    let action = match body["action"].as_str().unwrap_or("permit") {
        "deny" => PrefixListAction::Deny,
        _ => PrefixListAction::Permit,
    };
    let filter = AsPathFilter { name, match_type, action };
    match s.route_filter_mgr.add_as_path_filter(filter) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn list_route_maps(State(s): State<AppState>) -> Json<serde_json::Value> {
    let names = s.route_filter_mgr.list_route_maps();
    let mut result = Vec::new();
    for name in &names {
        let entries = s.route_filter_mgr.get_route_map(name);
        result.push(serde_json::json!({
            "name": name,
            "entries": entries,
        }));
    }
    Json(serde_json::json!(result))
}

pub(crate) async fn add_route_map_entry(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::routing::{PrefixListAction, RouteMapEntry, SetAction};
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("route-map name is required".into());
    }
    let action = match body["action"].as_str().unwrap_or("permit") {
        "deny" => PrefixListAction::Deny,
        _ => PrefixListAction::Permit,
    };
    let mut set_actions = Vec::new();
    if let Some(lp) = body["set_local_pref"].as_u64() {
        set_actions.push(SetAction::LocalPref(lp as u32));
    }
    if let Some(metric) = body["set_metric"].as_u64() {
        set_actions.push(SetAction::Metric(metric as u32));
    }
    if let Some(asn) = body["set_as_path_prepend"].as_u64() {
        set_actions.push(SetAction::AsPathPrepend(asn as u32));
    }
    let entry = RouteMapEntry {
        name: name.clone(),
        seq: body["seq"].as_u64().unwrap_or(10) as u32,
        action,
        match_prefix_list: body["match_prefix_list"].as_str().map(|s| s.to_string()),
        match_as_path: body["match_as_path"].as_str().map(|s| s.to_string()),
        match_community: body["match_community"].as_str().map(|s| s.to_string()),
        match_metric: body["match_metric"].as_u64().map(|v| v as u32),
        set_actions,
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match s.route_filter_mgr.add_route_map_entry(entry) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_route_map(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let entries = s.route_filter_mgr.get_route_map(&name);
    Json(serde_json::json!(entries))
}

pub(crate) async fn remove_route_map(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.route_filter_mgr.remove_route_map(&name) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Bridge VLAN ───────────────────────────────────────

pub(crate) async fn list_all_bridge_vlans(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let entries = s.bridge_vlan_mgr.list_all();
    Json(serde_json::json!(entries))
}

pub(crate) async fn list_bridge_vlans(
    State(s): State<AppState>,
    Path(bridge): Path<String>,
) -> Json<serde_json::Value> {
    let entries = s.bridge_vlan_mgr.list(&bridge);
    Json(serde_json::json!(entries))
}

pub(crate) async fn add_bridge_vlan(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::net::bridge_vlan::{BridgeVlanEntry, VlanFilterMode};
    let bridge = body["bridge"].as_str().unwrap_or("").to_string();
    let port = body["port"].as_str().unwrap_or("").to_string();
    let vlan_id = body["vlan_id"].as_u64().unwrap_or(0) as u16;
    let mode = match body["mode"].as_str().unwrap_or("trunk") {
        "access" => VlanFilterMode::Access,
        _ => VlanFilterMode::Trunk,
    };
    let tagged = body["tagged"].as_bool().unwrap_or(true);
    let pvid = body["pvid"].as_bool().unwrap_or(false);
    let untagged_vlans: Vec<u16> = body["untagged_vlans"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
        .unwrap_or_default();
    let tagged_vlans: Vec<u16> = body["tagged_vlans"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
        .unwrap_or_default();
    let entry = BridgeVlanEntry {
        bridge,
        port,
        mode,
        vlan_id,
        tagged,
        pvid,
        untagged_vlans,
        tagged_vlans,
    };
    match s.bridge_vlan_mgr.add(entry) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_bridge_vlan(
    State(s): State<AppState>,
    Path((bridge, port, vlan)): Path<(String, String, u16)>,
) -> Json<serde_json::Value> {
    match s.bridge_vlan_mgr.remove(&bridge, &port, vlan) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── BPF QoS ─────────────────────────────────────────

pub(crate) async fn list_bpf_qdiscs(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.bpf_qos_mgr.list_qdiscs().await {
        Ok(qdiscs) => Json(serde_json::json!(qdiscs)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn attach_bpf_qdisc(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let kind = match body["kind"].as_str() {
        Some("fq") => bpf_qos::BpfQdiscKind::Fq,
        Some("fq_codel") => bpf_qos::BpfQdiscKind::FqCodel,
        Some("cake") => bpf_qos::BpfQdiscKind::Cake,
        _ => bpf_qos::BpfQdiscKind::FqCodel,
    };
    let cfg = bpf_qos::BpfQdiscConfig {
        iface: body["iface"].as_str().unwrap_or("").to_string(),
        kind,
        rate: json_u64(&body["rate"]).unwrap_or(1_000_000_000),
        burst: json_u64(&body["burst"]),
        latency: json_u64(&body["latency"]),
    };
    match s.bpf_qos_mgr.attach_qdisc(&cfg).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn detach_bpf_qdisc(
    State(s): State<AppState>,
    Path(iface): Path<String>,
) -> Json<serde_json::Value> {
    match s.bpf_qos_mgr.detach_qdisc(&iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_bpf_qos_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.bpf_qos_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Plugins ─────────────────────────────────────────

pub(crate) async fn list_plugins(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.plugin_mgr.registry.list_plugins()))
}

pub(crate) async fn get_plugin_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.plugin_mgr.registry.get_status()))
}

// ─── Tenants ─────────────────────────────────────────

pub(crate) async fn list_tenants(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.tenancy_mgr.list_tenants().await {
        Ok(tenants) => Json(serde_json::json!(tenants)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_tenant(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tenant = tenancy::Tenant {
        id: body["id"].as_str().unwrap_or("").to_string(),
        name: body["name"].as_str().unwrap_or("").to_string(),
        domain: body["domain"].as_str().map(|s| s.to_string()),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
        max_users: json_u64(&body["max_users"]).map(|v| v as u32),
        max_bandwidth: json_u64(&body["max_bandwidth"]),
    };
    match s.tenancy_mgr.create_tenant(&tenant).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_tenant(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    match s.tenancy_mgr.delete_tenant(&id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
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
    Path((iface, classid)): Path<(String, u32)>,
) -> Json<serde_json::Value> {
    match s.qos_mgr.delete_class(&iface, classid).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── Conntrack ─────────────────────────────────────────

#[allow(clippy::await_holding_lock)]
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

#[allow(clippy::await_holding_lock)]
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

#[allow(clippy::await_holding_lock)]
pub(crate) async fn get_top_talkers(State(s): State<AppState>) -> Json<serde_json::Value> {
    let ct = s.ct_mgr.lock().await;
    match ct.top_talkers(20).await {
        Ok(talkers) => Json(serde_json::json!(talkers)),
        Err(e) => err(e.to_string()),
    }
}

#[allow(clippy::await_holding_lock)]
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

#[allow(clippy::await_holding_lock)]
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

// ─── PPPoE Failover ──────────────────────────────────

pub(crate) async fn list_uplinks(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.failover_mgr.list_uplinks().await {
        Ok(uplinks) => Json(serde_json::json!(uplinks)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_uplink(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let uplink = pppoe::failover::PppUplink {
        name: body["name"].as_str().unwrap_or("").to_string(),
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        isp_name: body["isp_name"].as_str().unwrap_or("").to_string(),
        priority: json_u64(&body["priority"]).unwrap_or(10) as u8,
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
        connected: json_bool(&body["connected"]).unwrap_or(true),
        failover_count: 0,
    };
    match s.failover_mgr.add_uplink(&uplink).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_uplink(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.failover_mgr.remove_uplink(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_failover_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.failover_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn trigger_failover(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.failover_mgr.trigger_failover().await {
        Ok(uplink) => Json(serde_json::json!({"active_uplink": uplink})),
        Err(e) => err(e.to_string()),
    }
}

// ─── VRRP ────────────────────────────────────────────

pub(crate) async fn list_vrrp_instances(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.vrrp_mgr.list_instances().await {
        Ok(instances) => Json(serde_json::json!(instances)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_vrrp_instance(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let inst = vrrp::VrrpInstance {
        vrid: json_u64(&body["vrid"]).unwrap_or(1) as u8,
        name: body["name"].as_str().unwrap_or("").to_string(),
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        priority: json_u64(&body["priority"]).unwrap_or(100) as u8,
        virtual_ip: body["virtual_ip"].as_str().unwrap_or("").to_string(),
        virtual_prefix: json_u64(&body["virtual_prefix"]).unwrap_or(24) as u8,
        advert_interval: json_u64(&body["advert_interval"]).unwrap_or(1) as u8,
        preempt: json_bool(&body["preempt"]).unwrap_or(true),
        enabled: json_bool(&body["enabled"]).unwrap_or(true),
    };
    match s.vrrp_mgr.create_instance(&inst).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_vrrp_instance(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.vrrp_mgr.delete_instance(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_vrrp_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.vrrp_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Address Lists ─────────────────────────────────────

pub(crate) async fn list_all_address_lists(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let names = s.address_list_mgr.list_names();
    let mut result = Vec::new();
    for name in &names {
        let entries = s.address_list_mgr.list(name);
        result.push(serde_json::json!({
            "name": name,
            "count": entries.len(),
            "entries": entries,
        }));
    }
    Json(serde_json::json!(result))
}

pub(crate) async fn list_address_list(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let entries = s.address_list_mgr.list(&name);
    Json(serde_json::json!(entries))
}

pub(crate) async fn add_address_list(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let addr_str = body["address"].as_str().unwrap_or("").to_string();
    let prefix = body["prefix"].as_u64().unwrap_or(32) as u8;
    let policy_str = body["policy"].as_str().unwrap_or("drop");
    let timeout_secs = body["timeout"].as_u64();
    let source = body["source"].as_str().unwrap_or("api");

    if name.is_empty() {
        return err("address list name is required".into());
    }
    let address: std::net::IpAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid IP address: {addr_str}")),
    };
    let policy = match policy_str {
        "allow" => crate::address_list::AddressListPolicy::Allow,
        "reject" => crate::address_list::AddressListPolicy::Reject,
        _ => crate::address_list::AddressListPolicy::Drop,
    };
    let timeout = timeout_secs.map(std::time::Duration::from_secs);

    match s
        .address_list_mgr
        .add(&name, address, prefix, policy, timeout, &source)
    {
        Ok(entry) => Json(serde_json::json!(entry)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_address_list_entry(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.address_list_mgr.remove(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn flush_address_list(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    s.address_list_mgr.flush(&name);
    ok()
}

// ─── Tools ──────────────────────────────────────────────

pub(crate) async fn tools_ping(
    Query(params): Query<ToolsPingParams>,
) -> Json<serde_json::Value> {
    use crate::tools::Pinger;
    let target: std::net::IpAddr = match params.target.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid target: {}", params.target)),
    };
    let count = params.count.unwrap_or(4).min(100);
    let timeout = std::time::Duration::from_secs(params.timeout.unwrap_or(5).min(30));
    let interval = std::time::Duration::from_secs(1);

    match Pinger::ping(target, count, interval, timeout).await {
        Ok(result) => Json(serde_json::json!(result)),
        Err(e) => err(format!("ping failed: {e}")),
    }
}

pub(crate) async fn tools_traceroute(
    Query(params): Query<ToolsTraceParams>,
) -> Json<serde_json::Value> {
    let target: std::net::IpAddr = match params.target.parse() {
        Ok(a) => a,
        Err(_) => return err(format!("invalid target: {}", params.target)),
    };
    let max_ttl = params.max_ttl.unwrap_or(30).min(64);
    let timeout = std::time::Duration::from_secs(params.timeout.unwrap_or(5).min(30));

    match crate::tools::traceroute::traceroute(target, max_ttl, timeout).await {
        Ok(result) => Json(serde_json::json!(result)),
        Err(e) => err(format!("traceroute failed: {e}")),
    }
}

// ─── DHCP Client ────────────────────────────────────────

pub(crate) async fn dhcp_client_discover(
    State(s): State<AppState>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    let config = crate::dhcp_client::DhcpClientConfig {
        interface: interface.clone(),
        ..Default::default()
    };
    match s.dhcp_client_mgr.discover(&interface, &config).await {
        Ok(lease) => Json(serde_json::json!(lease)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_client_status(
    State(s): State<AppState>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    match s.dhcp_client_mgr.get_status(&interface).await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_client_release(
    State(s): State<AppState>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    match s.dhcp_client_mgr.get_status(&interface).await {
        Ok(status) => {
            if let Some(lease) = status.lease {
                match s.dhcp_client_mgr.release(&interface, &lease).await {
                    Ok(_) => ok(),
                    Err(e) => err(e.to_string()),
                }
            } else {
                err("no active lease".into())
            }
        }
        Err(e) => err(e.to_string()),
    }
}

// ─── Scheduler ──────────────────────────────────────────

pub(crate) async fn list_scheduler_tasks(
    State(s): State<AppState>,
) -> Json<serde_json::Value> {
    let tasks = s.scheduler_mgr.list().await;
    Json(serde_json::json!(tasks))
}

pub(crate) async fn get_scheduler_task(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.scheduler_mgr.get(id).await {
        Some(task) => Json(serde_json::json!(task)),
        None => err(format!("task {id} not found")),
    }
}

pub(crate) async fn create_scheduler_task(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::scheduler::{ScheduledTask, ScheduledTaskAction, ScheduleInterval};

    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("task name is required".into());
    }

    let interval = match body["interval"].as_str().unwrap_or("once") {
        "once" => ScheduleInterval::Once,
        "hourly" => ScheduleInterval::Every(std::time::Duration::from_secs(3600)),
        "daily" => ScheduleInterval::Daily {
            hour: body["hour"].as_u64().unwrap_or(0) as u8,
            minute: body["minute"].as_u64().unwrap_or(0) as u8,
        },
        s if s.starts_with("every_") => {
            let secs = s
                .trim_start_matches("every_")
                .parse::<u64>()
                .unwrap_or(3600);
            ScheduleInterval::Every(std::time::Duration::from_secs(secs))
        }
        _ => ScheduleInterval::Once,
    };

    let action = match body["action"].as_str().unwrap_or("cleanup_expired") {
        "cleanup_expired" => ScheduledTaskAction::CleanupExpired,
        "notify" => {
            ScheduledTaskAction::Notify(body["message"].as_str().unwrap_or("").to_string())
        }
        "http_get" => {
            ScheduledTaskAction::HttpGet(body["url"].as_str().unwrap_or("").to_string())
        }
        "enable_interface" => ScheduledTaskAction::EnableInterface(
            body["interface"].as_str().unwrap_or("").to_string(),
        ),
        "disable_interface" => ScheduledTaskAction::DisableInterface(
            body["interface"].as_str().unwrap_or("").to_string(),
        ),
        a => return err(format!("unknown action: {a}")),
    };

    let task = ScheduledTask {
        id: 0,
        name,
        description: body["description"].as_str().unwrap_or("").to_string(),
        interval,
        action,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        last_run: None,
        last_result: None,
        run_count: 0,
    };

    match s.scheduler_mgr.add(task).await {
        Ok(id) => Json(serde_json::json!({"id": id})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_scheduler_task(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.scheduler_mgr.remove(id).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn toggle_scheduler_task(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let task = match s.scheduler_mgr.get(id).await {
        Some(t) => t,
        None => return err(format!("task {id} not found")),
    };
    match s.scheduler_mgr.set_enabled(id, !task.enabled).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── VRF ───────────────────────────────────────────────

pub(crate) async fn list_vrfs(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.vrf_mgr.list_vrfs().await {
        Ok(vrfs) => Json(serde_json::json!(vrfs)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_vrf(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.vrf_mgr.get_vrf(&name).await {
        Ok(vrf) => Json(serde_json::json!(vrf)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_vrf(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("VRF name is required".into());
    }
    let vrf = crate::vrf::VrfConfig {
        name,
        table_id: body["table_id"].as_u64().unwrap_or(0) as u32,
        interfaces: vec![],
        description: body["description"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.vrf_mgr.create_vrf(&vrf).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_vrf(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.vrf_mgr.delete_vrf(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_vrf_interface(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let iface = body["interface"].as_str().unwrap_or("").to_string();
    if iface.is_empty() {
        return err("interface name is required".into());
    }
    match s.vrf_mgr.add_interface(&name, &iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_vrf_interface(
    State(s): State<AppState>,
    Path((name, iface)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match s.vrf_mgr.remove_interface(&name, &iface).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── L2TP ──────────────────────────────────────────────

pub(crate) async fn list_l2tp_tunnels(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.l2tp_mgr.list_tunnels().await {
        Ok(tunnels) => Json(serde_json::json!(tunnels)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_l2tp_tunnel(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.l2tp_mgr.get_tunnel(&name).await {
        Ok(tunnel) => Json(serde_json::json!(tunnel)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_l2tp_tunnel(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("tunnel name is required".into());
    }
    let tunnel = crate::l2tp::L2tpTunnel {
        name,
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        local_id: body["local_id"].as_u64().unwrap_or(1) as u32,
        remote_id: body["remote_id"].as_u64().unwrap_or(2) as u32,
        enabled: body["enabled"].as_bool().unwrap_or(true),
        mtu: body["mtu"].as_u64().unwrap_or(1460) as u16,
        description: body["description"].as_str().map(|s| s.to_string()),
    };
    match s.l2tp_mgr.create_tunnel(&tunnel).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_l2tp_tunnel(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.l2tp_mgr.delete_tunnel(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn l2tp_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.l2tp_mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Netwatch ──────────────────────────────────────────

pub(crate) async fn list_netwatch(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.netwatch_mgr.list()))
}

pub(crate) async fn get_netwatch(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.netwatch_mgr.get(id) {
        Some(entry) => Json(serde_json::json!(entry)),
        None => err(format!("netwatch {id} not found")),
    }
}

pub(crate) async fn create_netwatch(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("name is required".into());
    }
    let target = body["target"].as_str().unwrap_or("").to_string();
    if target.is_empty() {
        return err("target is required".into());
    }
    use crate::netwatch::{NetwatchAction, NetwatchEntry, NetwatchStatus};
    let entry = NetwatchEntry {
        id: 0,
        name,
        target,
        interval_secs: body["interval"].as_u64().unwrap_or(30),
        timeout_secs: body["timeout"].as_u64().unwrap_or(5),
        retries: body["retries"].as_u64().unwrap_or(3) as u32,
        action_up: None,
        action_down: body["action_down"].as_str().map(|_| NetwatchAction::Log),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        status: NetwatchStatus::Unknown,
        last_up: None,
        last_down: None,
        consecutive_failures: 0,
        response_time_ms: 0.0,
    };
    match s.netwatch_mgr.add(&entry) {
        Ok(id) => Json(serde_json::json!({"id": id})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_netwatch(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.netwatch_mgr.remove(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn toggle_netwatch(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    let enabled = s.netwatch_mgr.get(id).map(|e| !e.enabled).unwrap_or(false);
    match s.netwatch_mgr.set_enabled(id, enabled) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn netwatch_down(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.netwatch_mgr.get_down()))
}

// ─── PCQ ───────────────────────────────────────────────

pub(crate) async fn list_pcq_classes(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.pcq_mgr.list_classes()))
}

pub(crate) async fn add_pcq_class(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::bpf_qos::{PcqClass, PcqHashMethod};
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("PCQ class name is required".into());
    }
    let hash_methods: Vec<PcqHashMethod> = body["hash_methods"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| match v.as_str() {
                    Some("src-address") => Some(PcqHashMethod::SrcAddress),
                    Some("dst-address") => Some(PcqHashMethod::DstAddress),
                    Some("src-port") => Some(PcqHashMethod::SrcPort),
                    Some("dst-port") => Some(PcqHashMethod::DstPort),
                    Some("both-addresses") => Some(PcqHashMethod::BothAddresses),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let class = PcqClass {
        name,
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        rate: body["rate"].as_u64().unwrap_or(10_000),
        ceil: body["ceil"].as_u64().unwrap_or(100_000),
        bucket_size: body["bucket_size"].as_u64().unwrap_or(16) as u32,
        hash_methods,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.pcq_mgr.add_class(class) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_pcq_class(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.pcq_mgr.remove_class(&name) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── SNMP ──────────────────────────────────────────────

pub(crate) async fn get_snmp_config(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.snmp_agent.get_config()))
}

pub(crate) async fn update_snmp_config(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::snmp::SnmpConfig;
    let config = SnmpConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        community_ro: body["community_ro"].as_str().unwrap_or("public").to_string(),
        community_rw: body["community_rw"].as_str().unwrap_or("private").to_string(),
        system_name: body["system_name"].as_str().unwrap_or("PungliOS").to_string(),
        system_location: body["system_location"].as_str().unwrap_or("Unknown").to_string(),
        system_contact: body["system_contact"].as_str().unwrap_or("admin@punglios.local").to_string(),
        listen_port: body["listen_port"].as_u64().unwrap_or(161) as u16,
        allowed_networks: vec![],
    };
    match s.snmp_agent.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_mib_entries(State(_s): State<AppState>) -> Json<serde_json::Value> {
    use crate::snmp::mib::mib2::Mib2;
    use crate::snmp::mib::private::PungliOSMib;
    let mut entries: Vec<serde_json::Value> = Mib2::all()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "oid": e.oid,
                "name": e.name,
                "type": e.r#type,
                "value": e.value,
            })
        })
        .collect();
    for entry in PungliOSMib::entries() {
        entries.push(serde_json::json!({
            "oid": entry.oid,
            "name": entry.name,
            "description": entry.description,
            "type": entry.r#type,
        }));
    }
    Json(serde_json::json!(entries))
}

// ─── IPsec ─────────────────────────────────────────────

pub(crate) async fn ipsec_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.ipsec_mgr.status().await {
        Ok(conns) => Json(serde_json::json!(conns)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipsec_connect(
    State(s): State<AppState>,
    Path(profile): Path<String>,
) -> Json<serde_json::Value> {
    match s.ipsec_mgr.connect(&profile).await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipsec_disconnect(
    State(s): State<AppState>,
    Path(profile): Path<String>,
) -> Json<serde_json::Value> {
    match s.ipsec_mgr.disconnect(&profile).await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

// ─── NTP ───────────────────────────────────────────────

pub(crate) async fn get_ntp_config(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.ntp_srv.get_config()))
}

pub(crate) async fn set_ntp_config(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::ntp::NtpConfig;
    let config = NtpConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        listen_port: body["listen_port"].as_u64().unwrap_or(123) as u16,
        stratum: body["stratum"].as_u64().unwrap_or(3) as u8,
        reference: body["reference"].as_str().unwrap_or("PungliOS").to_string(),
    };
    match s.ntp_srv.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_ntp_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "uptime_secs": s.ntp_srv.uptime_secs(),
        "current_timestamp": s.ntp_srv.current_timestamp(),
    }))
}

// ─── DNS DOH ───────────────────────────────────────────

#[derive(serde::Deserialize)]
pub(crate) struct DohParams {
    pub domain: String,
    pub server: Option<String>,
}

pub(crate) async fn dns_doh_resolve(
    Query(params): Query<DohParams>,
) -> Json<serde_json::Value> {
    use crate::dns::doh::DohResolver;
    let domain = &params.domain;
    let server = params.server.as_deref().unwrap_or("https://cloudflare-dns.com/dns-query");
    if domain.is_empty() {
        return err("domain is required".into());
    }
    match DohResolver::resolve(domain, server).await {
        Ok(resp) => Json(serde_json::json!(resp)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Bandwidth Test ────────────────────────────────────

pub(crate) async fn bandwidth_test(
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::tools::bw_test::BandwidthTest;
    let role = body["role"].as_str().unwrap_or("client");
    let target = body["target"].as_str().unwrap_or("127.0.0.1");
    let port = body["port"].as_u64().unwrap_or(5001) as u16;
    let duration = body["duration"].as_u64().unwrap_or(10);

    let result = if role == "server" {
        BandwidthTest::start_server(port, duration).await
    } else {
        BandwidthTest::start_client(target, port, duration).await
    };

    match result {
        Ok(r) => Json(serde_json::json!(r)),
        Err(e) => err(e.to_string()),
    }
}

// ─── Graphs ────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub(crate) struct GraphQuery {
    pub range: Option<u64>,
}

pub(crate) async fn get_graph_series(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<GraphQuery>,
) -> Json<serde_json::Value> {
    let data = match params.range {
        Some(range) => s.graph_store.get_series_range(&name, range),
        None => s.graph_store.get_series(&name),
    };
    Json(serde_json::json!(data))
}

pub(crate) async fn list_graph_metrics(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.graph_store.list_metrics()))
}

pub(crate) async fn add_graph_datapoint(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let value = body["value"].as_f64().unwrap_or(0.0);
    if name.is_empty() {
        return err("metric name is required".into());
    }
    s.graph_store.add_data(&name, value);
    ok()
}

// ─── Hotspot ───────────────────────────────────────────

pub(crate) async fn hotspot_list_sessions(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.hotspot_sessions.list()))
}

pub(crate) async fn hotspot_login(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let username = body["username"].as_str().unwrap_or("").to_string();
    let password = body["password"].as_str().unwrap_or("").to_string();
    let ip_str = body["ip"].as_str().unwrap_or("0.0.0.0");
    let mac = body["mac"].as_str().unwrap_or("00:00:00:00:00:00");

    if let Err(e) = crate::hotspot::HotspotAuth::validate(&username, &password) {
        return err(e.to_string());
    }

    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return err("invalid IP address".into()),
    };

    match s.hotspot_sessions.create(&username, &password, ip, mac) {
        Ok(session) => {
            s.hotspot_sessions.authorize(session.id).ok();
            s.hotspot_walled_garden.allow_ip(ip);
            Json(serde_json::json!(session))
        }
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn hotspot_logout(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match s.hotspot_sessions.logout(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn hotspot_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    let active = s.hotspot_sessions.list_active().len();
    let total = s.hotspot_sessions.list().len();
    Json(serde_json::json!({
        "active_sessions": active,
        "total_sessions": total,
    }))
}

pub(crate) async fn hotspot_walled_garden(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "domains": s.hotspot_walled_garden.list_domains(),
        "ips": s.hotspot_walled_garden.list_ips(),
    }))
}

// ─── BGP Inject ────────────────────────────────────────

pub(crate) async fn bgp_inject_route(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let dst = body["destination"].as_str().unwrap_or("").to_string();
    let prefix = body["prefix"].as_u64().unwrap_or(32) as u8;
    let nexthop = body["nexthop"].as_str().unwrap_or("0.0.0.0").to_string();
    let metric = body["metric"].as_u64().unwrap_or(100) as u32;
    match s.bgp_injector.inject_route(&dst, prefix, &nexthop, metric) {
        Ok(route) => Json(serde_json::json!(route)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bgp_list_injected(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.bgp_injector.get_routes()))
}

// ─── OSPF SPF ──────────────────────────────────────────

pub(crate) async fn ospf_run_spf(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.ospf_spf.run_spf() {
        Ok(routes) => Json(serde_json::json!(routes)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ospf_lsdb_status(State(_s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"lsdb_size": 0}))
}

// ─── LTE ───────────────────────────────────────────────

pub(crate) async fn lte_info(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.lte_mgr.get_info() {
        Some(info) => Json(serde_json::json!(info)),
        None => Json(serde_json::json!(null)),
    }
}

pub(crate) async fn lte_refresh(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.lte_mgr.refresh().await {
        Ok(info) => Json(serde_json::json!(info)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_connect(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.lte_mgr.connect().await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_disconnect(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.lte_mgr.disconnect().await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn lte_config(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.lte_mgr.get_config()))
}

pub(crate) async fn lte_set_config(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::lte::ModemConfig;
    let config = ModemConfig {
        apn: body["apn"].as_str().unwrap_or("internet").to_string(),
        pin: body["pin"].as_str().map(|s| s.to_string()),
        roam_allowed: body["roam_allowed"].as_bool().unwrap_or(false),
    };
    match s.lte_mgr.set_config(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

// ─── IPv6 DHCP ────────────────────────────────────────

pub(crate) async fn ipv6_dhcp_request_pd(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::ipv6::Dhcpv6PdConfig;
    let config = Dhcpv6PdConfig {
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        enabled: true,
        prefix_hint: body["prefix_hint"].as_str().unwrap_or("::/48").to_string(),
        prefix_length: body["prefix_length"].as_u64().unwrap_or(48) as u8,
        delegated_prefix: None,
        rapid_commit: true,
    };
    match s.ipv6_dhcp_mgr.request_pd(&config).await {
        Ok(prefix) => Json(serde_json::json!({"prefix": prefix})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipv6_radvd_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.ipv6_radvd_mgr.list().await))
}

pub(crate) async fn ipv6_radvd_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::ipv6::RouterAdvertisement;
    let ra = RouterAdvertisement {
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        managed: body["managed"].as_bool().unwrap_or(false),
        other_config: false,
        mtu: body["mtu"].as_u64().unwrap_or(1500) as u16,
        reachable_time: 0,
        retrans_timer: 0,
        cur_hop_limit: 64,
        prefix: body["prefix"].as_str().unwrap_or("2001:db8::").to_string(),
        prefix_length: body["prefix_length"].as_u64().unwrap_or(64) as u8,
        preferred_lifetime: 604800,
        valid_lifetime: 2592000,
        dns_servers: vec![],
    };
    match s.ipv6_radvd_mgr.add(ra).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipv6_firewall_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.ipv6_firewall.list_rules()))
}

pub(crate) async fn ipv6_firewall_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::ipv6::Ipv6FirewallRule;
    let rule = Ipv6FirewallRule {
        chain: body["chain"].as_str().unwrap_or("input").to_string(),
        action: body["action"].as_str().unwrap_or("accept").to_string(),
        src_addr: body["src_addr"].as_str().map(|s| s.to_string()),
        dst_addr: body["dst_addr"].as_str().map(|s| s.to_string()),
        protocol: body["protocol"].as_str().map(|s| s.to_string()),
        src_port: body["src_port"].as_u64().map(|v| v as u16),
        dst_port: body["dst_port"].as_u64().map(|v| v as u16),
        hop_limit: body["hop_limit"].as_u64().map(|v| v as u8),
        flow_label: body["flow_label"].as_u64().map(|v| v as u32),
        icmp_type: body["icmp_type"].as_u64().map(|v| v as u8),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    s.ipv6_firewall.add_rule(rule);
    ok()
}

pub(crate) async fn dhcp_relay_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.dhcp_relay_mgr.list()))
}

pub(crate) async fn dhcp_relay_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::dhcp::relay::DhcpRelayConfig;
    let server_str = body["server"].as_str().unwrap_or("0.0.0.0");
    let server: std::net::Ipv4Addr = match server_str.parse() {
        Ok(a) => a,
        Err(_) => return err("invalid server IP".into()),
    };
    let relay = DhcpRelayConfig {
        name: body["name"].as_str().unwrap_or("").to_string(),
        interfaces: body["interfaces"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        server,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.dhcp_relay_mgr.add(relay) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_relay_remove(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.dhcp_relay_mgr.remove(&name) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_snooping_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.dhcp_snooping.list()))
}

pub(crate) async fn dhcp_snooping_set(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::dhcp::snooping::DhcpSnoopingConfig;
    let config = DhcpSnoopingConfig {
        bridge: body["bridge"].as_str().unwrap_or("").to_string(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        trusted_ports: body["trusted_ports"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        verify_mac: body["verify_mac"].as_bool().unwrap_or(true),
    };
    s.dhcp_snooping.set(config);
    ok()
}

pub(crate) async fn igmp_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.igmp_snooping.list_groups()))
}

pub(crate) async fn igmp_set_enabled(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let enabled = body["enabled"].as_bool().unwrap_or(false);
    s.igmp_snooping.set_enabled(enabled);
    ok()
}

pub(crate) async fn stp_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.bridge_stp_mgr.list()))
}

pub(crate) async fn stp_get(
    State(s): State<AppState>,
    Path(bridge): Path<String>,
) -> Json<serde_json::Value> {
    match s.bridge_stp_mgr.get(&bridge) {
        Some(c) => Json(serde_json::json!(c)),
        None => err(format!("STP not configured for {bridge}")),
    }
}

pub(crate) async fn stp_set(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::bridge::stp::{StpConfig, StpMode};
    let mode_str = body["mode"].as_str().unwrap_or("rstp");
    let mode = match mode_str {
        "stp" => StpMode::Stp,
        "rstp" => StpMode::Rstp,
        "mstp" => StpMode::Mstp,
        _ => StpMode::Rstp,
    };
    let config = StpConfig {
        bridge: body["bridge"].as_str().unwrap_or("").to_string(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        mode,
        priority: body["priority"].as_u64().unwrap_or(32768) as u16,
        max_age: body["max_age"].as_u64().unwrap_or(20) as u16,
        hello_time: body["hello_time"].as_u64().unwrap_or(2) as u16,
        forward_delay: body["forward_delay"].as_u64().unwrap_or(15) as u16,
    };
    match s.bridge_stp_mgr.set(config) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bridge_acl_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.bridge_acl.list_rules()))
}

pub(crate) async fn bridge_acl_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::bridge::filter::BridgeAclRule;
    let rule = BridgeAclRule {
        bridge: body["bridge"].as_str().unwrap_or("").to_string(),
        action: body["action"].as_str().unwrap_or("accept").to_string(),
        src_mac: body["src_mac"].as_str().map(|s| s.to_string()),
        dst_mac: body["dst_mac"].as_str().map(|s| s.to_string()),
        vlan_id: body["vlan_id"].as_u64().map(|v| v as u16),
        src_port: body["src_port"].as_str().map(|s| s.to_string()),
        dst_port: body["dst_port"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    s.bridge_acl.add_rule(rule);
    ok()
}

pub(crate) async fn bridge_acl_remove(
    State(s): State<AppState>,
    Path(idx): Path<usize>,
) -> Json<serde_json::Value> {
    s.bridge_acl.remove_rule(idx);
    ok()
}

pub(crate) async fn lldp_neighbors(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.lldp_agent.list_neighbors()))
}

pub(crate) async fn bfd_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.bfd_mgr.list()))
}

pub(crate) async fn bfd_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::routing::BfdSession;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let session = BfdSession {
        neighbor: body["neighbor"].as_str().unwrap_or("").to_string(),
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        desired_tx_interval: body["desired_tx_interval"].as_u64().unwrap_or(100) as u32,
        required_rx_interval: body["required_rx_interval"].as_u64().unwrap_or(100) as u32,
        detection_multiplier: body["detection_multiplier"].as_u64().unwrap_or(3) as u8,
        state: "up".into(),
        last_seen: now,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.bfd_mgr.add(session) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bfd_remove(
    State(s): State<AppState>,
    Path(neighbor): Path<String>,
) -> Json<serde_json::Value> {
    match s.bfd_mgr.remove(&neighbor) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bfd_status(
    State(s): State<AppState>,
    Path(neighbor): Path<String>,
) -> Json<serde_json::Value> {
    let is_down = s.bfd_mgr.is_down(&neighbor, 30);
    Json(serde_json::json!({"neighbor": neighbor, "down": is_down}))
}

pub(crate) async fn dns_static_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.dns_static_mgr.list()))
}

pub(crate) async fn dns_static_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::dns::DnsStaticEntry;
    let entry = DnsStaticEntry {
        name: body["name"].as_str().unwrap_or("").to_string(),
        r#type: body["type"].as_str().unwrap_or("A").to_string(),
        value: body["value"].as_str().unwrap_or("").to_string(),
        ttl: body["ttl"].as_u64().unwrap_or(86400) as u32,
    };
    s.dns_static_mgr.add(entry);
    ok()
}

pub(crate) async fn dns_static_remove(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    s.dns_static_mgr.remove(&name);
    ok()
}

pub(crate) async fn ntp_client_config(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.ntp_client.get_config()))
}

pub(crate) async fn ntp_client_set_config(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::ntp::NtpClientConfig;
    let config = NtpClientConfig {
        enabled: body["enabled"].as_bool().unwrap_or(false),
        server: body["server"].as_str().unwrap_or("pool.ntp.org").to_string(),
        interval_secs: body["interval_secs"].as_u64().unwrap_or(3600),
    };
    s.ntp_client.set_config(config);
    ok()
}

pub(crate) async fn ntp_client_sync(State(s): State<AppState>) -> Json<serde_json::Value> {
    match s.ntp_client.sync().await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn mangle_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.mangle_table.list_rules()))
}

pub(crate) async fn mangle_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::firewall::MangleRule;
    let rule = MangleRule {
        chain: body["chain"].as_str().unwrap_or("prerouting").to_string(),
        action: body["action"].as_str().unwrap_or("mark-connection").to_string(),
        protocol: body["protocol"].as_str().map(|s| s.to_string()),
        src_addr: body["src_addr"].as_str().map(|s| s.to_string()),
        dst_addr: body["dst_addr"].as_str().map(|s| s.to_string()),
        src_port: body["src_port"].as_u64().map(|v| v as u16),
        dst_port: body["dst_port"].as_u64().map(|v| v as u16),
        conn_mark: body["conn_mark"].as_u64().map(|v| v as u32),
        packet_mark: body["packet_mark"].as_u64().map(|v| v as u32),
        route_mark: body["route_mark"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    s.mangle_table.add_rule(rule);
    ok()
}

pub(crate) async fn mangle_remove(
    State(s): State<AppState>,
    Path(idx): Path<usize>,
) -> Json<serde_json::Value> {
    s.mangle_table.remove_rule(idx);
    ok()
}

pub(crate) async fn pbr_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.pbr_mgr.list_rules()))
}

pub(crate) async fn pbr_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::routing::PbrRule;
    let rule = PbrRule {
        name: body["name"].as_str().unwrap_or("").to_string(),
        src_addr: body["src_addr"].as_str().map(|s| s.to_string()),
        dst_addr: body["dst_addr"].as_str().map(|s| s.to_string()),
        protocol: body["protocol"].as_str().map(|s| s.to_string()),
        src_port: body["src_port"].as_u64().map(|v| v as u16),
        dst_port: body["dst_port"].as_u64().map(|v| v as u16),
        mark: body["mark"].as_u64().map(|v| v as u32),
        table_id: body["table_id"].as_u64().unwrap_or(100) as u32,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    s.pbr_mgr.add_rule(rule);
    ok()
}

pub(crate) async fn pbr_remove(
    State(s): State<AppState>,
    Path(idx): Path<usize>,
) -> Json<serde_json::Value> {
    s.pbr_mgr.remove_rule(idx);
    ok()
}

pub(crate) async fn eoip_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.eoip_mgr.list()))
}

pub(crate) async fn eoip_create(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::tunnel::EoipTunnel;
    let tunnel = EoipTunnel {
        name: body["name"].as_str().unwrap_or("").to_string(),
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        tunnel_id: body["tunnel_id"].as_u64().unwrap_or(1) as u32,
        mtu: body["mtu"].as_u64().unwrap_or(1500) as u16,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.eoip_mgr.create(tunnel) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn eoip_delete(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    s.eoip_mgr.delete(&name);
    ok()
}

pub(crate) async fn gre_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.gre_mgr.list()))
}

pub(crate) async fn gre_create(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::tunnel::GreTunnel;
    let tunnel = GreTunnel {
        name: body["name"].as_str().unwrap_or("").to_string(),
        local_ip: body["local_ip"].as_str().unwrap_or("").to_string(),
        remote_ip: body["remote_ip"].as_str().unwrap_or("").to_string(),
        ttl: body["ttl"].as_u64().unwrap_or(64) as u8,
        mtu: body["mtu"].as_u64().unwrap_or(1476) as u16,
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    match s.gre_mgr.create(tunnel) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn gre_delete(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    s.gre_mgr.delete(&name);
    ok()
}

pub(crate) async fn flow_status(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "enabled": s.flow_exporter.is_enabled(),
        "collectors": s.flow_exporter.list_collectors(),
    }))
}

pub(crate) async fn flow_records(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.flow_exporter.get_records()))
}

pub(crate) async fn flow_clear(State(s): State<AppState>) -> Json<serde_json::Value> {
    s.flow_exporter.clear_records();
    ok()
}

pub(crate) async fn wol_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.wol_mgr.list()))
}

pub(crate) async fn wol_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::tools::WolTarget;
    let target = WolTarget {
        name: body["name"].as_str().unwrap_or("").to_string(),
        mac: body["mac"].as_str().unwrap_or("").to_string(),
        interface: body["interface"].as_str().map(|s| s.to_string()),
        broadcast_ip: body["broadcast_ip"]
            .as_str()
            .and_then(|s| s.parse().ok()),
    };
    s.wol_mgr.add(target);
    ok()
}

pub(crate) async fn wol_remove(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    s.wol_mgr.remove(&name);
    ok()
}

pub(crate) async fn wol_wake(
    State(s): State<AppState>,
    Path(mac): Path<String>,
) -> Json<serde_json::Value> {
    match s.wol_mgr.wake(&mac).await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

// ─── MPLS ──────────────────────────────────────────────

pub(crate) async fn mpls_interfaces(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.mpls_mgr.list_interfaces()))
}
pub(crate) async fn mpls_add_interface(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::mpls::MplsInterface;
    s.mpls_mgr.add_interface(MplsInterface { name: body["name"].as_str().unwrap_or("").to_string(), transport_address: body["transport_address"].as_str().unwrap_or("").to_string(), enabled: true, label_space: 0 }); ok()
}
pub(crate) async fn mpls_remove_interface(State(s): State<AppState>, Path(name): Path<String>) -> Json<serde_json::Value> { s.mpls_mgr.remove_interface(&name); ok() }
pub(crate) async fn mpls_lsps(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.mpls_mgr.list_lsps())) }

// ─── RIP ───────────────────────────────────────────────

pub(crate) async fn rip_interfaces(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.rip_mgr.list_interfaces())) }
pub(crate) async fn rip_add_interface(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::routing::RipInterface;
    s.rip_mgr.add_interface(RipInterface { name: body["name"].as_str().unwrap_or("").to_string(), enabled: body["enabled"].as_bool().unwrap_or(true), send_version: body["send_version"].as_u64().unwrap_or(2) as u8, receive_version: body["receive_version"].as_u64().unwrap_or(2) as u8, authentication: body["authentication"].as_str().map(|s| s.to_string()) }); ok()
}
pub(crate) async fn rip_remove_interface(State(s): State<AppState>, Path(name): Path<String>) -> Json<serde_json::Value> { s.rip_mgr.remove_interface(&name); ok() }
pub(crate) async fn rip_routes(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.rip_mgr.list_routes())) }

// ─── OSPFv3 ────────────────────────────────────────────

pub(crate) async fn ospfv3_areas(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.ospfv3_mgr.list_areas())) }
pub(crate) async fn ospfv3_add_area(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::routing::Ospfv3Area;
    s.ospfv3_mgr.add_area(Ospfv3Area { area_id: body["area_id"].as_str().unwrap_or("0.0.0.0").to_string(), interfaces: body["interfaces"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(), enabled: body["enabled"].as_bool().unwrap_or(true), instance_id: body["instance_id"].as_u64().unwrap_or(0) as u8 }); ok()
}
pub(crate) async fn ospfv3_remove_area(State(s): State<AppState>, Path(id): Path<String>) -> Json<serde_json::Value> { s.ospfv3_mgr.remove_area(&id); ok() }

// ─── Traffic Generator ─────────────────────────────────

pub(crate) async fn traffic_gen_start(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    match crate::tools::traffic_gen::generate_udp(body["target"].as_str().unwrap_or("127.0.0.1"), body["port"].as_u64().unwrap_or(5000) as u16, body["packet_size"].as_u64().unwrap_or(1472) as usize, body["packets"].as_u64().unwrap_or(1000)).await {
        Ok(result) => Json(serde_json::json!(result)), Err(e) => err(e.to_string()),
    }
}

// ─── Sniffer ───────────────────────────────────────────

pub(crate) async fn sniffer_status(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!({"enabled": s.sniffer.is_enabled(), "packet_count": s.sniffer.get_packets().len()})) }
pub(crate) async fn sniffer_set_enabled(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> { s.sniffer.set_enabled(body["enabled"].as_bool().unwrap_or(false)); ok() }
pub(crate) async fn sniffer_packets(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.sniffer.get_packets())) }
pub(crate) async fn sniffer_clear(State(s): State<AppState>) -> Json<serde_json::Value> { s.sniffer.clear(); ok() }

// ─── RADIUS CoA ────────────────────────────────────────

pub(crate) async fn radius_coa_disconnect(State(s): State<AppState>, Path(session): Path<String>) -> Json<serde_json::Value> {
    match s.radius_coa.disconnect(&session).await { Ok(output) => Json(serde_json::json!({"output": output})), Err(e) => err(e.to_string()) }
}

// ─── Backup ────────────────────────────────────────────

pub(crate) async fn backup_config(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.backup_mgr.get_config())) }
pub(crate) async fn backup_set_config(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::backup::BackupConfig;
    s.backup_mgr.set_config(BackupConfig { enabled: body["enabled"].as_bool().unwrap_or(false), path: body["path"].as_str().unwrap_or("/etc/punglios/backup").to_string(), upload_url: body["upload_url"].as_str().map(|s| s.to_string()), keep_count: body["keep_count"].as_u64().unwrap_or(7) as u32, schedule_cron: body["schedule_cron"].as_str().unwrap_or("0 3 * * *").to_string() }); ok()
}
pub(crate) async fn backup_run(State(s): State<AppState>) -> Json<serde_json::Value> { match s.backup_mgr.run_backup().await { Ok(o) => Json(serde_json::json!({"output": o})), Err(e) => err(e.to_string()) } }

// ─── Email ─────────────────────────────────────────────

pub(crate) async fn email_config(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.email_mgr.get_config())) }
pub(crate) async fn email_set_config(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::tools::EmailConfig;
    s.email_mgr.set_config(EmailConfig { enabled: body["enabled"].as_bool().unwrap_or(false), server: body["server"].as_str().unwrap_or("smtp.example.com").to_string(), port: body["port"].as_u64().unwrap_or(587) as u16, username: body["username"].as_str().map(|s| s.to_string()), password: body["password"].as_str().map(|s| s.to_string()), from: body["from"].as_str().unwrap_or("punglios@local").to_string(), to: body["to"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(), use_tls: body["use_tls"].as_bool().unwrap_or(true) }); ok()
}

// ─── UPnP ──────────────────────────────────────────────

pub(crate) async fn upnp_status(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!({"enabled": s.upnp_mgr.is_enabled(), "mappings": s.upnp_mgr.list_mappings()})) }
pub(crate) async fn upnp_set_enabled(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> { s.upnp_mgr.set_enabled(body["enabled"].as_bool().unwrap_or(false)); ok() }
pub(crate) async fn upnp_add_mapping(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::upnp::UpnpMapping;
    let ip: std::net::Ipv4Addr = match body["internal_ip"].as_str().unwrap_or("0.0.0.0").parse() { Ok(a) => a, Err(_) => return err("invalid IP".into()) };
    s.upnp_mgr.add_mapping(UpnpMapping { id: (s.upnp_mgr.list_mappings().len() + 1) as u64, external_port: body["external_port"].as_u64().unwrap_or(0) as u16, internal_port: body["internal_port"].as_u64().unwrap_or(0) as u16, internal_ip: ip, protocol: body["protocol"].as_str().unwrap_or("tcp").to_string(), duration_secs: body["duration"].as_u64().unwrap_or(0) as u32, description: body["description"].as_str().unwrap_or("").to_string() }); ok()
}
pub(crate) async fn upnp_remove_mapping(State(s): State<AppState>, Path(id): Path<u64>) -> Json<serde_json::Value> { s.upnp_mgr.remove_mapping(id); ok() }

// ─── 802.1X ────────────────────────────────────────────

pub(crate) async fn dot1x_ports(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.dot1x_mgr.list_ports())) }
pub(crate) async fn dot1x_set_port(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::dot1x::Dot1xPort;
    s.dot1x_mgr.set_port(Dot1xPort { name: body["name"].as_str().unwrap_or("").to_string(), enabled: body["enabled"].as_bool().unwrap_or(true), auth_type: body["auth_type"].as_str().unwrap_or("mac-auth-bypass").to_string(), timeout_secs: body["timeout"].as_u64().unwrap_or(30) as u32 }); ok()
}
pub(crate) async fn dot1x_remove_port(State(s): State<AppState>, Path(name): Path<String>) -> Json<serde_json::Value> { s.dot1x_mgr.remove_port(&name); ok() }

// ─── DDNS ──────────────────────────────────────────────

pub(crate) async fn ddns_config(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.ddns_mgr.get_config())) }
pub(crate) async fn ddns_set_config(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::cloud::DdnsConfig;
    s.ddns_mgr.set_config(DdnsConfig { enabled: body["enabled"].as_bool().unwrap_or(false), service: body["service"].as_str().unwrap_or("cloudflare").to_string(), hostname: body["hostname"].as_str().unwrap_or("").to_string(), username: body["username"].as_str().map(|s| s.to_string()), password: body["password"].as_str().map(|s| s.to_string()), interval_minutes: body["interval"].as_u64().unwrap_or(5) as u32 }); ok()
}
pub(crate) async fn ddns_update(State(s): State<AppState>) -> Json<serde_json::Value> { match s.ddns_mgr.update().await { Ok(o) => Json(serde_json::json!({"output": o})), Err(e) => err(e.to_string()) } }

// ─── System Health ─────────────────────────────────────

pub(crate) async fn health_status(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!(s.health_mon.get_status())) }
pub(crate) async fn health_update(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    use crate::health::HealthStatus;
    s.health_mon.update(HealthStatus { temperature: body["temperature"].as_f64().unwrap_or(45.0), voltage: body["voltage"].as_f64().unwrap_or(12.0), cpu_usage: body["cpu_usage"].as_f64().unwrap_or(15.0), memory_usage: body["memory_usage"].as_f64().unwrap_or(30.0), uptime_secs: body["uptime"].as_u64().unwrap_or(0) }); ok()
}

// ─── IP Accounting ─────────────────────────────────────

pub(crate) async fn accounting_status(State(s): State<AppState>) -> Json<serde_json::Value> { Json(serde_json::json!({"enabled": s.ip_accounting.is_enabled(), "records": s.ip_accounting.get_records()})) }
pub(crate) async fn accounting_set_enabled(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> { s.ip_accounting.set_enabled(body["enabled"].as_bool().unwrap_or(false)); ok() }
pub(crate) async fn accounting_clear(State(s): State<AppState>) -> Json<serde_json::Value> { s.ip_accounting.clear(); ok() }

// ─── Layer7 ────────────────────────────────────────────

pub(crate) async fn layer7_list(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(s.layer7_mgr.list()))
}

pub(crate) async fn layer7_add(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use crate::firewall::Layer7Pattern;
    let name = body["name"].as_str().unwrap_or("").to_string();
    let pattern = body["pattern"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("pattern name is required".into());
    }
    match s.layer7_mgr.add(Layer7Pattern {
        name,
        pattern,
        description: body["description"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    }) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn layer7_get(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.layer7_mgr.get(&name) {
        Some(p) => Json(serde_json::json!(p)),
        None => err(format!("pattern '{name}' not found")),
    }
}

pub(crate) async fn layer7_remove(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match s.layer7_mgr.remove(&name) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn layer7_toggle(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let enabled = s
        .layer7_mgr
        .get(&name)
        .map(|p| !p.enabled)
        .unwrap_or(false);
    match s.layer7_mgr.set_enabled(&name, enabled) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn layer7_match(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let data_str = body["data"].as_str().unwrap_or("");
    let data = data_str.as_bytes();
    let matched = s.layer7_mgr.match_against(data);
    Json(serde_json::json!({
        "matched": matched.iter().map(|p| &p.name).collect::<Vec<_>>(),
        "count": matched.len(),
    }))
}
