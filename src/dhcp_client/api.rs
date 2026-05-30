#![allow(dead_code)]
use crate::api::{err, ok};
use crate::dhcp_client::{DhcpClientConfig, DhcpClientManager, MockDhcpClient};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn dhcp_client_discover(
    State(mgr): State<Arc<DhcpClientManager<MockDhcpClient>>>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    let config = DhcpClientConfig {
        interface: interface.clone(),
        ..Default::default()
    };
    match mgr.discover(&interface, &config).await {
        Ok(lease) => Json(serde_json::json!(lease)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_client_status(
    State(mgr): State<Arc<DhcpClientManager<MockDhcpClient>>>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.get_status(&interface).await {
        Ok(status) => Json(serde_json::json!(status)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn dhcp_client_release(
    State(mgr): State<Arc<DhcpClientManager<MockDhcpClient>>>,
    Path(interface): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.get_status(&interface).await {
        Ok(status) => {
            if let Some(lease) = status.lease {
                match mgr.release(&interface, &lease).await {
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
