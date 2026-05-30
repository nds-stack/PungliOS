use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: u64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricInfo {
    pub name: String,
    pub unit: String,
    pub data_points: usize,
    pub max_points: usize,
    pub step_secs: u64,
}

pub struct GraphStore {
    series: Mutex<HashMap<String, Vec<DataPoint>>>,
    max_points: usize,
    step_secs: u64,
}

impl GraphStore {
    pub fn new(max_points: usize, step_secs: u64) -> Self {
        Self {
            series: Mutex::new(HashMap::new()),
            max_points,
            step_secs,
        }
    }

    pub fn add_data(&self, name: &str, value: f64) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let dp = DataPoint { timestamp: ts, value };
        let mut series = self.series.lock().unwrap();
        let entry = series.entry(name.to_string()).or_default();
        entry.push(dp);
        if entry.len() > self.max_points {
            entry.drain(0..entry.len() - self.max_points);
        }
    }

    pub fn get_series(&self, name: &str) -> Vec<DataPoint> {
        self.series
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    pub fn list_metrics(&self) -> Vec<MetricInfo> {
        let series = self.series.lock().unwrap();
        series
            .iter()
            .map(|(name, data)| MetricInfo {
                name: name.clone(),
                unit: "bps".into(),
                data_points: data.len(),
                max_points: self.max_points,
                step_secs: self.step_secs,
            })
            .collect()
    }

    pub fn get_series_range(&self, name: &str, range_secs: u64) -> Vec<DataPoint> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(range_secs);
        self.series
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|dp| dp.timestamp >= cutoff)
            .collect()
    }
}

impl Default for GraphStore {
    fn default() -> Self {
        Self::new(288, 300)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let store = GraphStore::new(10, 60);
        store.add_data("bandwidth", 1_000_000.0);
        store.add_data("bandwidth", 2_000_000.0);
        let data = store.get_series("bandwidth");
        assert_eq!(data.len(), 2);
        assert_eq!(data[1].value, 2_000_000.0);
    }

    #[test]
    fn test_max_points() {
        let store = GraphStore::new(3, 60);
        for i in 0..10 {
            store.add_data("cpu", i as f64);
        }
        assert_eq!(store.get_series("cpu").len(), 3);
    }

    #[test]
    fn test_list_metrics() {
        let store = GraphStore::new(10, 60);
        store.add_data("rx_bytes", 100.0);
        store.add_data("tx_bytes", 200.0);
        assert_eq!(store.list_metrics().len(), 2);
    }
}
