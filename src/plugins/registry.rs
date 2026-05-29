use super::types::*;
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type PluginEntry = (Box<dyn Plugin>, PluginState);

#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    async fn on_load(&self) -> Result<()>;
    async fn on_unload(&self) -> Result<()>;
    async fn on_enable(&self) -> Result<()>;
    async fn on_disable(&self) -> Result<()>;
}

pub struct PluginRegistry {
    plugins: Arc<RwLock<HashMap<String, PluginEntry>>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn register(&self, plugin: Box<dyn Plugin>) -> Result<()> {
        let name = plugin.name().to_string();
        let mut plugins = self.plugins.write().expect("lock poisoned");
        if plugins.contains_key(&name) {
            bail!("plugin '{name}' already registered");
        }
        plugin.on_load().await?;
        plugins.insert(name, (plugin, PluginState::Loaded));
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn enable(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().expect("lock poisoned");
        let (plugin, state) = plugins
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("plugin '{name}' not found"))?;
        plugin.on_enable().await?;
        *state = PluginState::Enabled;
        Ok(())
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn disable(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().expect("lock poisoned");
        let (plugin, state) = plugins
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("plugin '{name}' not found"))?;
        plugin.on_disable().await?;
        *state = PluginState::Disabled;
        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().expect("lock poisoned");
        plugins
            .values()
            .map(|(p, state)| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
                description: p.description().to_string(),
                enabled: matches!(state, PluginState::Enabled),
            })
            .collect()
    }

    pub fn get_status(&self) -> PluginManagerStatus {
        let plugins = self.plugins.read().expect("lock poisoned");
        let mut enabled = 0;
        let mut errored = 0;
        for (_, (_, state)) in plugins.iter() {
            match state {
                PluginState::Enabled => enabled += 1,
                PluginState::Error(_) => errored += 1,
                _ => {}
            }
        }
        PluginManagerStatus {
            total_plugins: plugins.len(),
            enabled_plugins: enabled,
            errored_plugins: errored,
        }
    }
}

pub struct PluginManager {
    pub registry: PluginRegistry,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            registry: PluginRegistry::new(),
        }
    }
}
