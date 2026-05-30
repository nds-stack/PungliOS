#![allow(dead_code)]
use crate::api::{err, ok};
use crate::bonding::{BondInterface, BondMode, BondingManager, MockBondingBackend};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn list_bonds(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
) -> Json<serde_json::Value> {
    match mgr.list_bonds().await {
        Ok(bonds) => Json(serde_json::json!(bonds)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn get_bond(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.get_bond(&name).await {
        Ok(bond) => Json(serde_json::json!(bond)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn create_bond(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return err("bond name is required".into());
    }
    let mode_str = body["mode"].as_str().unwrap_or("active-backup");
    let mode = BondMode::from_str(mode_str).unwrap_or(BondMode::ActiveBackup);

    let slaves: Vec<String> = body["slaves"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let bond = BondInterface {
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

    match mgr.create_bond(&bond).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn delete_bond(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.delete_bond(&name).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn add_bond_slave(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let slave = body["slave"].as_str().unwrap_or("").to_string();
    if slave.is_empty() {
        return err("slave name is required".into());
    }
    match mgr.add_slave(&name, &slave).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn remove_bond_slave(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
    Path((name, slave)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    match mgr.remove_slave(&name, &slave).await {
        Ok(_) => ok(),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn bond_status(
    State(mgr): State<Arc<BondingManager<MockBondingBackend>>>,
) -> Json<serde_json::Value> {
    match mgr.get_status().await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}
