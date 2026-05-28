use clap::Subcommand;

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Load YAML config file
    Load { path: Option<String> },
    /// Save current config as YAML
    Save { path: Option<String> },
    /// Show current config
    Show,
    /// Apply config transactionally
    Apply { path: Option<String> },
    /// Rollback last transaction
    Rollback,
}
