#![allow(dead_code)]
use crate::api::{err, ok};
use crate::hotspot::{HotspotAuth, SessionManager, WalledGarden};
use axum::{
    Json,
    extract::{Path, State},
};
use std::net::IpAddr;
use std::sync::Arc;

pub(crate) async fn hotspot_list_sessions(
    State(mgr): State<Arc<SessionManager>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!(mgr.list()))
}

pub(crate) async fn hotspot_login(
    State(mgr): State<Arc<SessionManager>>,
    State(wg): State<Arc<WalledGarden>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let username = body["username"].as_str().unwrap_or("").to_string();
    let password = body["password"].as_str().unwrap_or("").to_string();
    let ip_str = body["ip"].as_str().unwrap_or("0.0.0.0");
    let mac = body["mac"].as_str().unwrap_or("00:00:00:00:00:00");

    if let Err(e) = HotspotAuth::validate(&username, &password) {
        return err(e.to_string());
    }

    let ip: IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return err("invalid IP address".into()),
    };

    match mgr.create(&username, &password, ip, mac) {
        Ok(session) => {
            // Auto-authorize (in production: trigger RADIUS)
            mgr.authorize(session.id).ok();
            // Add to walled garden
            wg.allow_ip(ip);
            Json(serde_json::json!(session))
        }
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn hotspot_logout(
    State(mgr): State<Arc<SessionManager>>,
    Path(id): Path<u64>,
) -> Json<serde_json::Value> {
    match mgr.logout(id) {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn hotspot_status(
    State(mgr): State<Arc<SessionManager>>,
) -> Json<serde_json::Value> {
    let active = mgr.list_active().len();
    let total = mgr.list().len();
    Json(serde_json::json!({
        "active_sessions": active,
        "total_sessions": total,
        "uptime_secs": 0,
    }))
}

pub(crate) async fn hotspot_walled_garden(
    State(wg): State<Arc<WalledGarden>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "domains": wg.list_domains(),
        "ips": wg.list_ips(),
    }))
}
