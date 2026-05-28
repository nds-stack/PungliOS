# RULES.md — Coding Standards & Folder Structure

## Folder Structure

```
Rust/PungliOS/
├── AGENTS.md          ← AI agent guide
├── PlanPRD.md         ← PRD & vision
├── PROJECT.md         ← arsitektur & filosofi
├── RULES.md           ← file ini
├── TODO.md            ← roadmap & status
├── README.md          ← dokumentasi publik
├── CHANGELOG.md       ← release notes
├── Cargo.toml         ← Rust manifest
│
├── src/
│   ├── main.rs        ← binary entry point
│   ├── lib.rs         ← library root (re-exports)
│   │
│   ├── traits/        ← core abstractions (1.1a)
│   │   ├── mod.rs
│   │   ├── netlink.rs       # NetlinkIfaces, NetlinkFirewall, NetlinkQos
│   │   └── mock.rs          # MockBackend (in-memory)
│   │
│   ├── net/           ← networking modules
│   │   ├── mod.rs
│   │   ├── iface.rs         # Interface manager (1.2)
│   │   ├── bridge.rs        # Bridge management
│   │   ├── vlan.rs          # VLAN management
│   │   └── route.rs         # Static routing (1.9)
│   │
│   ├── firewall/      ← nftables wrapper (1.3)
│   │   ├── mod.rs
│   │   ├── zone.rs          # Zone-based model
│   │   ├── rule.rs          # Rule generation
│   │   ├── chain.rs         # Chain management
│   │   └── nat.rs           # NAT manager (1.8)
│   │
│   ├── qos/           ← traffic control (1.4)
│   │   ├── mod.rs
│   │   ├── htb.rs           # HTB qdisc
│   │   ├── class.rs         # Per-user class
│   │   └── fq_codel.rs      # fq_codel leaf
│   │
│   ├── conntrack/     ← connection tracking (1.5)
│   │   ├── mod.rs
│   │   ├── tuning.rs        # Auto-tuning params
│   │   └── fast_track.rs    # Fast-track optimization
│   │
│   ├── config/        ← configuration engine (1.6)
│   │   ├── mod.rs
│   │   ├── schema.rs        # YAML schema + validation
│   │   ├── storage.rs       # bincode binary serialize
│   │   └── transaction.rs   # Commit/rollback
│   │
│   ├── cli/           ← CLI interface (1.7)
│   │   ├── mod.rs
│   │   ├── commands/        # Per-command modules
│   │   │   ├── mod.rs
│   │   │   ├── interface.rs
│   │   │   ├── firewall.rs
│   │   │   ├── qos.rs
│   │   │   └── config.rs
│   │   └── tui.rs           # ratatui interactive shell
│   │
│   └── pppoe/         ← PPPoE server (Phase 2)
│       ├── mod.rs
│       ├── discovery.rs     # PADI/PADO/PADR/PADS/PADT
│       ├── session.rs       # PPP negotiation (LCP, IPCP)
│       └── auth.rs          # PAP/CHAP/MS-CHAPv2
│
├── tests/
│   ├── integration/
│   │   └── test_all_managers.rs
│   ├── common/
│   │   └── mod.rs           # Shared mock setup
│   └── tests.rs
│
├── benches/
│   └── traits.rs
│
└── examples/          # TBD — minimal examples planned
```

## Rust Conventions

### Naming

```rust
// Modules, functions, variables: snake_case
mod netlink_backend;
fn create_interface(name: &str) -> Result<Interface>;
let interface_count = 42;

// Structs, enums, traits: PascalCase
struct InterfaceManager { ... }
enum FirewallAction { ... }
trait NetlinkIfaces { ... }

// Constants: SCREAMING_SNAKE_CASE
const MAX_INTERFACES: usize = 1024;
const DEFAULT_MTU: u16 = 1500;
```

### Error Handling

```rust
// Prefer Result over panic
fn add_interface(&self, name: &str) -> Result<Interface, PungliError>;

// Custom error types with thiserror
#[derive(Error, Debug)]
pub enum PungliError {
    #[error("interface {0} not found")]
    InterfaceNotFound(String),
    #[error("netlink error: {0}")]
    Netlink(#[from] std::io::Error),
}

// Use anyhow for application-level
fn main() -> anyhow::Result<()> { ... }
```

### Async Patterns

```rust
// All networking ops via tokio
use tokio::net::UnixStream;

// Trait methods should be async
#[async_trait]
pub trait NetlinkIfaces: Send + Sync {
    async fn list(&self) -> Result<Vec<Interface>>;
    async fn create(&self, iface: &InterfaceConfig) -> Result<Interface>;
    async fn delete(&self, name: &str) -> Result<()>;
}
```

### Trait-Based Design (Critical)

```rust
// Every kernel interaction goes through a trait
// Mock implementation for tests, real for production

#[async_trait]
pub trait NetlinkFirewall: Send + Sync {
    async fn add_rule(&self, rule: &FirewallRule) -> Result<()>;
    async fn list_rules(&self) -> Result<Vec<FirewallRule>>;
    async fn delete_rule(&self, handle: u64) -> Result<()>;
}

// Mock backend (in-memory)
pub struct MockBackend {
    interfaces: Arc<RwLock<HashMap<String, Interface>>>,
    rules: Arc<RwLock<Vec<FirewallRule>>>,
}

// Real backend (nftnl + nlink)
pub struct RealBackend {
    nftnl_conn: nftnl::Connection,
    nlink_conn: nlink::Connection,
}
```

### Safety Rules

1. **No unsafe** tanpa documented justification
2. **No raw pointers** — gunakan references / `Box` / `Arc`
3. **No transmute** — gunakan safe abstractions
4. **Lock ordering** — dokumentasikan order `Arc<RwLock<T>>` untuk mencegah deadlock
5. **No blocking ops di async context** — gunakan `tokio::task::spawn_blocking`

### Testing Standards

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn setup_mock() -> InterfaceManager {
        let backend = MockBackend::new();
        InterfaceManager::new(backend)
    }

    #[tokio::test]
    async fn test_create_interface() {
        let mgr = setup_mock();
        let iface = mgr.create("eth0").await.unwrap();
        assert_eq!(iface.name, "eth0");
    }
}
```

### Logging

```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(self))]
pub async fn create_interface(&self, name: &str) -> Result<Interface> {
    info!(name, "creating interface");
    // ...
}
```

## Build Configuration

```toml
[package]
name = "punglios"
version = "0.1.0"
edition = "2024"
description = "Rust-Native ISP/WISP Management Platform"

[features]
default = ["mock"]
mock = []              # In-memory mock backend (tests / Windows dev)
real = ["nftnl", "nlink"]  # Production backend (Linux only)

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
rkyv = { version = "0.7", features = ["validation"] }
clap = { version = "4", features = ["derive"] }
ratatui = "0.29"
tracing = "0.1"
tracing-subscriber = "0.3"
thiserror = "2"
anyhow = "1"

# Optional: Real backend (Linux only)
nftnl = { version = "0.9", optional = true }
nlink = { version = "0.17", features = ["full"], optional = true }

[dev-dependencies]
tokio-test = "0.4"
criterion = "0.5"

# NOTE: Real backend dependencies (nftnl, nlink) are behind the "real" feature flag.
# See Cargo.toml for current dependency structure.
# [target.'cfg(target_os = "linux")'.dependencies] — not used; uses optional = true instead
```

## Dependency Rules

| Rule | Detail |
|------|--------|
| Audit | Setiap crate baru wajib dicek: maintenance, unsafe %, license, downloads |
| Justify | Setiap dependency wajib ada comment reason di Cargo.toml |
| Minimize | Prefer stdlib over external crates |
| No C deps | Kecuali kernel interface (nftnl, nlink wrap C libs internally) |
| Features | Gunakan feature flags untuk conditional compilation (mock vs real) |

---

*Dibaca oleh AI agent sebelum coding. Update jika ada perubahan standar.*
