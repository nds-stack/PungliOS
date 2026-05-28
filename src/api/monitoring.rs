#![cfg(feature = "api")]

use crate::api::AppState;
use axum::{
    extract::State,
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::sync::Mutex;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

struct CpuSnapshot {
    prev_total: u64,
    prev_idle: u64,
}

static CPU_STATE: Mutex<Option<CpuSnapshot>> = Mutex::new(None);

pub(crate) async fn collect_monitoring_data(s: &AppState) -> serde_json::Value {
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

pub(crate) async fn monitoring_loop(app: AppState, tx: broadcast::Sender<String>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let data = collect_monitoring_data(&app).await;
        let msg = data.to_string();
        let _ = tx.send(msg);
    }
}

pub(crate) async fn monitoring_stream(
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

fn read_proc_stat() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let line = s.lines().next()?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let total: u64 = parts[1..]
        .iter()
        .filter_map(|p| p.parse::<u64>().ok())
        .sum();
    let idle: u64 = parts[4].parse().ok()?;
    Some((total, idle))
}

fn compute_cpu_percent(total: u64, idle: u64, prev_total: u64, prev_idle: u64) -> f64 {
    let dtotal = total.saturating_sub(prev_total);
    let didle = idle.saturating_sub(prev_idle);
    if dtotal == 0 {
        return 0.0;
    }
    100.0 * (1.0 - didle as f64 / dtotal as f64)
}

pub(crate) fn get_system_info() -> (f64, u64, u64, u64) {
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

        if let Some((total, idle)) = read_proc_stat() {
            let mut state = CPU_STATE.lock().unwrap();
            if let Some(prev) = state.as_ref() {
                cpu = compute_cpu_percent(total, idle, prev.prev_total, prev.prev_idle);
            }
            *state = Some(CpuSnapshot {
                prev_total: total,
                prev_idle: idle,
            });
        }
    }

    (cpu, mem_total, mem_used, uptime)
}
