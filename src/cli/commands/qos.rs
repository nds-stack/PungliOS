use clap::Subcommand;

#[derive(Subcommand)]
pub enum QosCommands {
    /// Add a qdisc to an interface
    AddQdisc {
        iface: String,
        kind: String,
        handle: u32,
        parent: u32,
        #[arg(long)]
        rate: Option<u64>,
        #[arg(long)]
        ceil: Option<u64>,
    },
    /// Delete a qdisc
    DeleteQdisc { iface: String, handle: u32 },
    /// Add a traffic class
    AddClass {
        iface: String,
        classid: u32,
        parent: u32,
        rate: u64,
        #[arg(long)]
        ceil: Option<u64>,
        #[arg(long)]
        priority: Option<u8>,
    },
    /// Delete a traffic class
    DeleteClass { iface: String, classid: u32 },
    /// Create HTB root qdisc
    HtbRoot { iface: String, rate: u64 },
    /// Create a per-user class
    UserClass {
        iface: String,
        classid: u32,
        rate: u64,
        ceil: u64,
    },
    /// Attach fq_codel leaf to a class
    FqCodel { iface: String, parent: u32 },
}
