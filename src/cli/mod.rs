pub mod commands;
pub mod tui;

use clap::Subcommand;
use commands::config::ConfigCommands;
use commands::firewall::FirewallCommands;
use commands::interface::InterfaceCommands;
use commands::qos::QosCommands;

#[derive(Subcommand)]
pub enum CliCommand {
    /// Interface management
    #[command(subcommand)]
    Interface(InterfaceCommands),

    /// Firewall and NAT management
    #[command(subcommand)]
    Firewall(FirewallCommands),

    /// QoS and traffic shaping
    #[command(subcommand)]
    Qos(QosCommands),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Launch interactive terminal UI
    Shell,

    /// Start REST API + Web UI server
    #[cfg(feature = "api")]
    Serve {
        /// Listen address (default: 0.0.0.0:3000)
        #[arg(default_value = "0.0.0.0:3000")]
        addr: String,
    },
}
