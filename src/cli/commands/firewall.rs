use clap::Subcommand;

#[derive(Subcommand)]
pub enum FirewallCommands {
    /// List rules in a zone
    ListRules { zone: String },
    /// Add a rule to a zone/chain
    AddRule {
        zone: String,
        chain: String,
        #[arg(long)]
        protocol: Option<String>,
        #[arg(long)]
        src_addr: Option<String>,
        #[arg(long)]
        dst_addr: Option<String>,
        #[arg(long)]
        src_port: Option<u16>,
        #[arg(long)]
        dst_port: Option<u16>,
        #[arg(long)]
        action: String,
    },
    /// Delete a rule by handle
    DeleteRule { handle: u64 },
    /// Flush all rules
    Flush,
    /// Create a firewall zone
    CreateZone {
        name: String,
        #[arg(long)]
        interfaces: Vec<String>,
    },
    #[command(name = "set-policy")]
    /// Set zone default policy
    SetPolicy {
        zone: String,
        chain: String,
        policy: String,
    },
    /// List NAT rules
    ListNat,
    /// Add SNAT rule
    AddSnat {
        iface: String,
        #[arg(long)]
        to_addr: Option<String>,
    },
    /// Add DNAT rule
    AddDnat {
        iface: String,
        #[arg(long)]
        dst_addr: Option<String>,
        #[arg(long)]
        to_addr: Option<String>,
        #[arg(long)]
        to_port: Option<u16>,
    },
    /// Add masquerade
    Masquerade { iface: String },
    /// Delete a NAT rule
    DeleteNat { handle: u64 },
}
