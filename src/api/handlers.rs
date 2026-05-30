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
