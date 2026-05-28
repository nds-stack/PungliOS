use clap::Subcommand;

#[derive(Subcommand)]
pub enum InterfaceCommands {
    /// List all interfaces
    List,
    /// Show interface details
    Show {
        name: String,
    },
    /// Create a new interface
    Create {
        name: String,
        #[arg(long)]
        mtu: Option<u16>,
        #[arg(long)]
        address: Vec<String>,
        #[arg(long)]
        vlan: Option<u16>,
        #[arg(long)]
        bridge: Option<String>,
    },
    /// Delete an interface
    Delete {
        name: String,
    },
    /// Set interface up
    Up {
        name: String,
    },
    /// Set interface down
    Down {
        name: String,
    },
    /// Set interface MTU
    SetMtu {
        name: String,
        mtu: u16,
    },
    /// Create VLAN interface
    Vlan {
        parent: String,
        vlan_id: u16,
    },
    /// Add interface to bridge
    Bridge {
        iface: String,
        bridge: String,
    },
}
