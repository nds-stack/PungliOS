#![allow(dead_code)]
use crate::api::err;
use crate::ipsec::IpsecManager;
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;

pub(crate) async fn ipsec_status(
    State(mgr): State<Arc<IpsecManager>>,
) -> Json<serde_json::Value> {
    match mgr.status().await {
        Ok(conns) => Json(serde_json::json!(conns)),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipsec_connect(
    State(mgr): State<Arc<IpsecManager>>,
    Path(profile): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.connect(&profile).await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}

pub(crate) async fn ipsec_disconnect(
    State(mgr): State<Arc<IpsecManager>>,
    Path(profile): Path<String>,
) -> Json<serde_json::Value> {
    match mgr.disconnect(&profile).await {
        Ok(output) => Json(serde_json::json!({"output": output})),
        Err(e) => err(e.to_string()),
    }
}
