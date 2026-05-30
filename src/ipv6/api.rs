#![allow(dead_code)]
use crate::api::{err, ok};
use crate::ipv6::{Dhcpv6Manager, Dhcpv6PdConfig, MockDhcpv6Backend, RadvdManager, RouterAdvertisement, Ipv6Firewall, Ipv6FirewallRule};
use axum::{Json, extract::State};
use std::sync::Arc;

pub(crate) async fn dhcpv6_request_pd(
    State(mgr): State<Arc<Dhcpv6Manager<MockDhcpv6Backend>>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let config = Dhcpv6PdConfig {
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        enabled: true, prefix_hint: body["prefix_hint"].as_str().unwrap_or("::/48").to_string(),
        prefix_length: body["prefix_length"].as_u64().unwrap_or(48) as u8,
        delegated_prefix: None, rapid_commit: true,
    };
    match mgr.request_pd(&config).await {
        Ok(prefix) => Json(serde_json::json!({"prefix": prefix})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn radvd_list(State(mgr): State<Arc<RadvdManager>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.list().await))
}

pub(crate) async fn radvd_add(
    State(mgr): State<Arc<RadvdManager>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let ra = RouterAdvertisement {
        interface: body["interface"].as_str().unwrap_or("").to_string(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        managed: body["managed"].as_bool().unwrap_or(false),
        other_config: false, mtu: body["mtu"].as_u64().unwrap_or(1500) as u16,
        reachable_time: 0, retrans_timer: 0, cur_hop_limit: 64,
        prefix: body["prefix"].as_str().unwrap_or("2001:db8::").to_string(),
        prefix_length: body["prefix_length"].as_u64().unwrap_or(64) as u8,
        preferred_lifetime: 604800, valid_lifetime: 2592000,
        dns_servers: vec![],
    };
    match mgr.add(ra).await {
        Ok(_) => ok(), Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipv6_firewall_list(State(fw): State<Arc<Ipv6Firewall>>) -> Json<serde_json::Value> {
    Json(serde_json::json!(fw.list_rules()))
}

pub(crate) async fn ipv6_firewall_add(
    State(fw): State<Arc<Ipv6Firewall>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
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
    fw.add_rule(rule);
    ok()
}
