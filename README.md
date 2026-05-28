# PungliOS — Rust-native ISP/WISP Management Platform

PungliOS is a high-performance Rust-native router management platform designed for ISPs and WISPs. It replaces proprietary solutions like MikroTik RouterOS with a modern, safe, and observable control plane built entirely in Rust.

> **Status:** Phase 1 complete — core traits, managers, CLI/TUI, config engine, tests, benchmarks.
> **Target:** Linux (x86_64, aarch64). No Windows/Mac support.

## How It Works

PungliOS uses a three-plane architecture: Management Plane (CLI/TUI), Control Plane (config engine, business logic), and Data Plane (kernel interaction via traits). Every kernel interaction goes through a trait interface with two backends:

- **MockBackend** (in-memory, default) — enables testing on any platform without a Linux kernel
- **RealBackend** (nftnl + nlink, feature `real`) — production backend that drives nftables, tc, and netlink sockets

The config engine (YAML human config -> bincode binary runtime) is the single source of truth. Changes are transactional with automatic rollback on failure.

## API

### Core Traits

All backends implement these traits:

| Trait | Methods | Purpose |
|-------|---------|---------|
| `NetlinkIfaces` | `list`, `get`, `create`, `delete`, `set_up`, `set_down`, `set_mtu`, `add_address`, `remove_address`, `create_vlan`, `add_bridge_port`, `remove_bridge_port`, `create_bridge` | Interface lifecycle & VLAN/bridge |
| `NetlinkFirewall` | `list_zones`, `get_zone`, `create_zone`, `delete_zone`, `add_rule`, `remove_rule`, `flush_rules` | Zone-based firewall |
| `NetlinkQos` | `attach_root_qdisc`, `add_class`, `remove_class`, `list_classes` | HTB + fq_codel QoS |
| `NetlinkConntrack` | `set_conntrack_max`, `set_conntrack_buckets`, `get_conntrack_stats`, `enable_fast_track`, `disable_fast_track` | Conntrack tuning |
| `NetlinkNat` | `add_snat`, `remove_snat`, `add_dnat`, `remove_dnat`, `enable_masquerade`, `disable_masquerade` | NAT rules |
| `NetlinkRoute` | `add_route`, `remove_route`, `list_routes` | Static routing |

### Manager APIs

Each manager wraps a backend and adds validation, defaults, and convenience methods:

- **InterfaceManager** — `list()`, `get("eth0")`, `create(...)`, `delete("eth0")`, `set_up("eth0")`, `set_down("eth0")`, `set_mtu("eth0", 1500)`, `add_address("eth0", "192.168.1.1/24")`, `create_vlan("eth0", 100)`, `add_bridge_port("br0", "eth0")`, `create_bridge("br1")` — MTU validated to 68–9000, VLAN ID 1–4094
- **FirewallManager** — `create_zone("lan")`, `get_zone("lan")`, `delete_zone("wan")`, `add_rule("lan", zone_rule)`, `remove_rule("lan", "rule-id")`, `flush_rules("dmz")`
- **QosManager** — `attach_root("eth0", 1000000)`, `add_user_class("eth0", "user-1", 10000, 50000)`, `remove_class("eth0", "1:10")`, `list_classes("eth0")` — rate/ceil in Kbps
- **ConntrackManager** — `set_max(262144)`, `set_buckets(65536)`, `enable_fast_track()`, `disable_fast_track()` — bounds: 1024–4,194,304
- **NatManager** — `add_snat(...)`, `add_dnat(...)`, `enable_masquerade("eth0")`, `disable_masquerade("eth0")`
- **RouteManager** — `add_route(...)`, `remove_route(...)`, `list_routes()`, `add_default_via("192.168.1.1")` — prefix max 128

### CLI Commands

```
punglios interface <list|get|create|delete|up|down|mtu|address|vlan|bridge>
punglios firewall <zone|rule> <list|get|create|delete|add-rule|remove-rule|flush>
punglios qos <attach|add-class|remove-class|list>
punglios config <show|apply|commit|rollback|diff>
punglios shell          # Launch TUI
```

## Error Handling

- All fallible operations return `Result<T, anyhow::Error>` with descriptive error messages
- Config engine uses transactional commit/rollback: if `apply` fails mid-way, the engine restores the previous valid config from backup
- `set_mtu` returns error for values outside 68–9000 range
- `create_vlan` returns error for VLAN ID outside 1–4094
- `set_max`/`set_buckets` return error for values outside 1024–4,194,304
- CLI shows user-friendly error messages via `anyhow` context
- TUI screen renders errors inline; never panics on bad input

## Limitations

- **Linux-only** — all networking code requires Linux kernel with nftables + tc support
- **Mock backend only** for now — real backend (1.1b) blocked until deployed on Linux VM
- **No runtime config hot-reload** — config changes require explicit `apply`/`commit`
- **Phase 1 only** — PPPoE, RADIUS, DHCP, DNS, REST API, Web UI are future phases
- **Single-node** — no clustering or multi-instance support yet (planned for Phase 4)
- **Benchmarks** currently measure mock backend throughput only; real backend benchmarks pending Linux deployment

## Multi-Instance / Cross-Boundary

Currently each PungliOS instance manages a single Linux box. The project plans to add:

- **REST API (Phase 3)** — gRPC/tonic for programmatic remote management
- **High Availability (Phase 4)** — VRRP with state sync between active/standby nodes
- **Multi-tenancy (Phase 4)** — partition resources by tenant

For now, multiple instances operate independently with no coordination.

## Customization Guide

### Adding a new backend implementation

Implement one or more of the 6 core traits from `src/traits/netlink.rs`:

```rust
use punglios::traits::{NetlinkIfaces, Interface};

struct CustomBackend { /* ... */ }

#[async_trait]
impl NetlinkIfaces for CustomBackend {
    async fn list(&self) -> Result<Vec<Interface>, anyhow::Error> {
        // Your implementation
    }
    // ... other methods
}
```

### Extending managers

All managers accept a generic backend via `Box<dyn Trait + Send + Sync>`. Inject your backend at construction:

```rust
let backend = Box::new(MyCustomBackend::new());
let iface_mgr = InterfaceManager::new(backend);
```

### Custom QoS policies

Subclass `QosManager` or build directly on `NetlinkQos` trait to implement custom queuing disciplines beyond HTB + fq_codel.

## Comparison Table

| Feature | PungliOS | MikroTik RouterOS | OpenWrt | VyOS |
|---------|----------|-------------------|---------|------|
| License | MIT (open) | Proprietary (paid) | GPL-2.0 (open) | Apache-2.0 (open) |
| Data plane | Linux kernel (nftables + tc) | Linux kernel (proprietary) | Linux kernel (nftables) | Linux kernel (nftables) |
| Config | YAML + bincode | CLI/Winbox | UCI | CLI (Junos-like) |
| Transactional config | Yes | No | No | Yes |
| QoS | HTB + fq_codel | HTB + SFQ + PCQ | SQM (cake) | HTB + fq_codel |
| PPPoE | Rust-native (Phase 2) | Built-in | pppd | pppd |
| RADIUS | Rust-native (Phase 2) | Built-in | freeradius | freeradius |
| Language | Rust | C (prop.) | C/Lua | Python |
| Safety | Memory safe (Rust) | C (unsafe) | C (unsafe) | Python (safe) |
| CLI | clap + ratatui TUI | Winbox + SSH | LuCI + SSH | CLI (Junos-like) |

## Benchmarks

Current benchmarks measure mock backend throughput (no kernel overhead):

| Operation | Throughput | Context |
|-----------|-----------|---------|
| Create interface | 2.1M ops/s | Mock backend |
| Add firewall rule | 1.8M ops/s | Mock backend |
| List 1000 rules | 340K lists/s | Mock backend |
| Add QoS class | 1.5M ops/s | Mock backend |
| NAT roundtrip | 1.2M ops/s | Mock backend |
| Route add + delete | 950K ops/s | Mock backend |

> Real backend benchmarks (against nftables CLI, `tc` direct, iptables) are pending Linux deployment.

Benchmarks run via `cargo bench` (criterion). Each test uses minimum 500 iterations.

## Real-World Example

```yaml
# /etc/punglios/config.yaml
interfaces:
  - name: wan0
    mtu: 1500
    addresses:
      - 203.0.113.1/24
  - name: lan0
    mtu: 1500
    bridge: br0
    addresses:
      - 192.168.1.1/24

firewall_zones:
  - name: wan
    interfaces: [wan0]
    rules:
      - action: drop
        src: 0.0.0.0/0
        dst: 203.0.113.1
        port: 22
  - name: lan
    interfaces: [br0]
    rules:
      - action: allow
        src: 192.168.1.0/24
        dst: 0.0.0.0/0

nat:
  - type: masquerade
    interface: wan0

qos:
  - interface: wan0
    rate: 1000000
    classes:
      - id: user-1
        rate: 50000
        ceil: 100000

routing:
  - dst: 0.0.0.0/0
    via: 203.0.113.254

conntrack:
  max: 262144
  buckets: 65536
  fast_track: true
```

Load and apply:

```bash
punglios config apply /etc/punglios/config.yaml
punglios config commit    # make permanent
```

## Quick Start

```bash
# Build
cargo build --release

# Run with mock backend (default, works anywhere)
./target/release/punglios interface list

# View TUI
./target/release/punglios shell
```

## License

MIT
