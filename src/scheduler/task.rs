use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleInterval {
    Once,
    Every(Duration),
    Daily { hour: u8, minute: u8 },
    Weekly { day: u8, hour: u8, minute: u8 },
    Cron(String),
}

impl std::fmt::Display for ScheduleInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Once => write!(f, "once"),
            Self::Every(d) => write!(f, "every {}s", d.as_secs()),
            Self::Daily { hour, minute } => write!(f, "daily {hour:02}:{minute:02}"),
            Self::Weekly { day, hour, minute } => {
                write!(f, "weekly day={day} {hour:02}:{minute:02}")
            }
            Self::Cron(expr) => write!(f, "cron({expr})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduledTaskAction {
    HttpGet(String),
    HttpPost(String, String),
    CliCommand(Vec<String>),
    Script(String),
    EnableInterface(String),
    DisableInterface(String),
    RestartService(String),
    CleanupExpired,
    Notify(String),
}

impl std::fmt::Display for ScheduledTaskAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpGet(url) => write!(f, "http_get {url}"),
            Self::HttpPost(url, _) => write!(f, "http_post {url}"),
            Self::CliCommand(args) => write!(f, "cli {}", args.join(" ")),
            Self::Script(s) => write!(f, "script {s}"),
            Self::EnableInterface(iface) => write!(f, "enable_interface {iface}"),
            Self::DisableInterface(iface) => write!(f, "disable_interface {iface}"),
            Self::RestartService(svc) => write!(f, "restart_service {svc}"),
            Self::CleanupExpired => write!(f, "cleanup_expired"),
            Self::Notify(msg) => write!(f, "notify {msg}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub interval: ScheduleInterval,
    pub action: ScheduledTaskAction,
    pub enabled: bool,
    pub last_run: Option<u64>,
    pub last_result: Option<String>,
    pub run_count: u64,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

type TaskFn = Box<dyn Fn() -> tokio::task::JoinHandle<()> + Send + Sync>;

pub struct Scheduler {
    tasks: HashMap<u64, ScheduledTask>,
    handles: HashMap<u64, TaskFn>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            handles: HashMap::new(),
        }
    }

    pub fn add(&mut self, task: ScheduledTask) -> Result<u64> {
        if task.name.is_empty() {
            bail!("task name cannot be empty");
        }
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::SeqCst);
        let mut t = task;
        t.id = id;
        self.tasks.insert(id, t);
        Ok(id)
    }

    pub fn remove(&mut self, id: u64) -> Result<()> {
        self.tasks
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("task {id} not found"))?;
        self.handles.remove(&id);
        Ok(())
    }

    pub fn get(&self, id: u64) -> Option<&ScheduledTask> {
        self.tasks.get(&id)
    }

    pub fn list(&self) -> Vec<&ScheduledTask> {
        let mut tasks: Vec<_> = self.tasks.values().collect();
        tasks.sort_by_key(|t| t.id);
        tasks
    }

    pub fn update(&mut self, id: u64, task: ScheduledTask) -> Result<()> {
        if !self.tasks.contains_key(&id) {
            bail!("task {id} not found");
        }
        let mut t = task;
        t.id = id;
        self.tasks.insert(id, t);
        Ok(())
    }

    pub fn set_enabled(&mut self, id: u64, enabled: bool) -> Result<()> {
        let task = self
            .tasks
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("task {id} not found"))?;
        task.enabled = enabled;
        Ok(())
    }

    pub fn record_run(&mut self, id: u64, result: String) {
        if let Some(task) = self.tasks.get_mut(&id) {
            task.last_run = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            task.last_result = Some(result);
            task.run_count += 1;
        }
    }

    pub fn attach_handler(&mut self, id: u64, handler: TaskFn) {
        self.handles.insert(id, handler);
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScheduledTaskManager {
    inner: Mutex<Scheduler>,
}

impl ScheduledTaskManager {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Scheduler::new()),
        }
    }

    pub async fn add(&self, task: ScheduledTask) -> Result<u64> {
        self.inner.lock().await.add(task)
    }

    pub async fn remove(&self, id: u64) -> Result<()> {
        self.inner.lock().await.remove(id)
    }

    pub async fn get(&self, id: u64) -> Option<ScheduledTask> {
        self.inner.lock().await.get(id).cloned()
    }

    pub async fn list(&self) -> Vec<ScheduledTask> {
        self.inner
            .lock()
            .await
            .list()
            .into_iter()
            .cloned()
            .collect()
    }

    pub async fn update(&self, id: u64, task: ScheduledTask) -> Result<()> {
        self.inner.lock().await.update(id, task)
    }

    pub async fn set_enabled(&self, id: u64, enabled: bool) -> Result<()> {
        self.inner.lock().await.set_enabled(id, enabled)
    }

    pub async fn record_run(&self, id: u64, result: String) {
        self.inner.lock().await.record_run(id, result);
    }
}

impl Default for ScheduledTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_task() {
        let mgr = ScheduledTaskManager::new();
        let task = ScheduledTask {
            id: 0,
            name: "cleanup".into(),
            description: "Cleanup expired entries".into(),
            interval: ScheduleInterval::Every(Duration::from_secs(3600)),
            action: ScheduledTaskAction::CleanupExpired,
            enabled: true,
            last_run: None,
            last_result: None,
            run_count: 0,
        };
        let id = mgr.add(task).await.unwrap();
        let fetched = mgr.get(id).await.unwrap();
        assert_eq!(fetched.name, "cleanup");
    }

    #[tokio::test]
    async fn test_list_tasks() {
        let mgr = ScheduledTaskManager::new();
        assert_eq!(mgr.list().await.len(), 0);
        mgr.add(ScheduledTask {
            id: 0,
            name: "task1".into(),
            description: String::new(),
            interval: ScheduleInterval::Once,
            action: ScheduledTaskAction::CleanupExpired,
            enabled: true,
            last_run: None,
            last_result: None,
            run_count: 0,
        })
        .await
        .unwrap();
        assert_eq!(mgr.list().await.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_task() {
        let mgr = ScheduledTaskManager::new();
        let id = mgr
            .add(ScheduledTask {
                id: 0,
                name: "temp".into(),
                description: String::new(),
                interval: ScheduleInterval::Once,
                action: ScheduledTaskAction::CleanupExpired,
                enabled: true,
                last_run: None,
                last_result: None,
                run_count: 0,
            })
            .await
            .unwrap();
        mgr.remove(id).await.unwrap();
        assert!(mgr.get(id).await.is_none());
    }

    #[tokio::test]
    async fn test_record_run() {
        let mgr = ScheduledTaskManager::new();
        let id = mgr
            .add(ScheduledTask {
                id: 0,
                name: "test".into(),
                description: String::new(),
                interval: ScheduleInterval::Once,
                action: ScheduledTaskAction::CleanupExpired,
                enabled: true,
                last_run: None,
                last_result: None,
                run_count: 0,
            })
            .await
            .unwrap();
        mgr.record_run(id, "success".into()).await;
        let task = mgr.get(id).await.unwrap();
        assert_eq!(task.run_count, 1);
        assert_eq!(task.last_result.unwrap(), "success");
    }

    #[test]
    fn test_interval_display() {
        let i = ScheduleInterval::Every(Duration::from_secs(60));
        assert_eq!(i.to_string(), "every 60s");
        let d = ScheduleInterval::Daily {
            hour: 3,
            minute: 0,
        };
        assert_eq!(d.to_string(), "daily 03:00");
    }

    #[test]
    fn test_action_display() {
        let a = ScheduledTaskAction::CleanupExpired;
        assert_eq!(a.to_string(), "cleanup_expired");
        let n = ScheduledTaskAction::Notify("test".into());
        assert_eq!(n.to_string(), "notify test");
    }
}
