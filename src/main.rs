use clap::Parser;
#[cfg(feature = "api")]
use punglios::api::AppState;
use punglios::cli::CliCommand;
use punglios::cli::commands::config::ConfigCommands;
use punglios::cli::commands::firewall::FirewallCommands;
use punglios::cli::commands::interface::InterfaceCommands;
use punglios::cli::commands::qos::QosCommands;

#[derive(Parser)]
#[command(name = "punglios", about = "Rust-Native ISP/WISP Management Platform")]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!("PungliOS starting");

    match cli.command {
        CliCommand::Interface(cmd) => handle_interface(cmd).await?,
        CliCommand::Firewall(cmd) => handle_firewall(cmd).await?,
        CliCommand::Qos(cmd) => handle_qos(cmd).await?,
        CliCommand::Config(cmd) => handle_config(cmd).await?,
        CliCommand::Shell => {
            tracing::info!("Interactive shell launched");
            // TODO: ratatui TUI
            println!("Interactive shell — coming soon");
        }
        #[cfg(feature = "api")]
        CliCommand::Serve { addr } => {
            let state = AppState::new();
            state.start_monitoring();
            let app = punglios::api::router(state.clone());

            #[cfg(feature = "web")]
            let app = {
                let web_router = punglios::web::router(state.clone());
                app.merge(web_router)
            };

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            tracing::info!("API server listening on {addr}");
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn handle_interface(cmd: InterfaceCommands) -> anyhow::Result<()> {
    match cmd {
        InterfaceCommands::List => {
            println!("Interfaces:");
            // TODO: use InterfaceManager with real backend
        }
        InterfaceCommands::Show { name } => {
            println!("Interface: {name}");
        }
        InterfaceCommands::Create {
            name,
            mtu,
            address,
            vlan,
            bridge,
        } => {
            println!(
                "Creating interface {name}: mtu={mtu:?}, addresses={address:?}, vlan={vlan:?}, bridge={bridge:?}"
            );
        }
        InterfaceCommands::Delete { name } => {
            println!("Deleting interface {name}");
        }
        InterfaceCommands::Up { name } => {
            println!("Setting {name} up");
        }
        InterfaceCommands::Down { name } => {
            println!("Setting {name} down");
        }
        InterfaceCommands::SetMtu { name, mtu } => {
            println!("Setting {name} MTU to {mtu}");
        }
        InterfaceCommands::Vlan { parent, vlan_id } => {
            println!("Creating VLAN {parent}.{vlan_id}");
        }
        InterfaceCommands::Bridge { iface, bridge } => {
            println!("Adding {iface} to bridge {bridge}");
        }
    }
    Ok(())
}

async fn handle_firewall(cmd: FirewallCommands) -> anyhow::Result<()> {
    match cmd {
        FirewallCommands::ListRules { zone } => {
            println!("Rules in zone {zone}:");
        }
        FirewallCommands::AddRule {
            zone,
            chain,
            protocol: _,
            src_addr: _,
            dst_addr: _,
            src_port: _,
            dst_port: _,
            action,
        } => {
            println!("Adding rule to {zone}/{chain}: action={action}");
        }
        FirewallCommands::DeleteRule { handle } => {
            println!("Deleting rule {handle}");
        }
        FirewallCommands::Flush => {
            println!("Flushing all rules");
        }
        FirewallCommands::CreateZone { name, interfaces } => {
            println!("Creating zone {name} with interfaces {interfaces:?}");
        }
        FirewallCommands::SetPolicy {
            zone,
            chain,
            policy,
        } => {
            println!("Setting {zone}/{chain} policy to {policy}");
        }
        FirewallCommands::ListNat => {
            println!("NAT rules:");
        }
        FirewallCommands::AddSnat { iface, to_addr } => {
            println!("Adding SNAT on {iface} -> {to_addr:?}");
        }
        FirewallCommands::AddDnat {
            iface,
            dst_addr,
            to_addr,
            to_port,
        } => {
            println!("Adding DNAT on {iface}: {dst_addr:?} -> {to_addr:?}:{to_port:?}");
        }
        FirewallCommands::Masquerade { iface } => {
            println!("Adding masquerade on {iface}");
        }
        FirewallCommands::DeleteNat { handle } => {
            println!("Deleting NAT rule {handle}");
        }
    }
    Ok(())
}

async fn handle_qos(cmd: QosCommands) -> anyhow::Result<()> {
    match cmd {
        QosCommands::AddQdisc {
            iface,
            kind,
            handle: _,
            parent: _,
            rate: _,
            ceil: _,
        } => {
            println!("Adding {kind} qdisc on {iface}");
        }
        QosCommands::DeleteQdisc { iface, handle } => {
            println!("Deleting qdisc {handle} from {iface}");
        }
        QosCommands::AddClass {
            iface,
            classid,
            parent: _,
            rate: _,
            ceil: _,
            priority: _,
        } => {
            println!("Adding class {classid} on {iface}");
        }
        QosCommands::DeleteClass { iface, classid } => {
            println!("Deleting class {classid} from {iface}");
        }
        QosCommands::HtbRoot { iface, rate } => {
            println!("Creating HTB root on {iface} at {rate}bps");
        }
        QosCommands::UserClass {
            iface,
            classid,
            rate,
            ceil,
        } => {
            println!("Creating user class {classid} on {iface}: {rate}/{ceil}");
        }
        QosCommands::FqCodel { iface, parent } => {
            println!("Attaching fq_codel to {iface} parent {parent}");
        }
    }
    Ok(())
}

async fn handle_config(cmd: ConfigCommands) -> anyhow::Result<()> {
    match cmd {
        ConfigCommands::Load { path } => {
            println!("Loading config from {path:?}");
        }
        ConfigCommands::Save { path } => {
            println!("Saving config to {path:?}");
        }
        ConfigCommands::Show => {
            println!("Current config:");
        }
        ConfigCommands::Apply { path } => {
            println!("Applying config from {path:?}");
        }
        ConfigCommands::Rollback => {
            println!("Rolling back last transaction");
        }
    }
    Ok(())
}
