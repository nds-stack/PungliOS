# Changelog

All notable changes to PungliOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0] - 2026-05-30

### Added (Sprint 1 — Easy Wins)

- **Address List (5.1):** `src/address_list/` — CRUD address list with IPv4/IPv6 prefix matching, auto-expiry via timeout, thread-safe `AddressListManager`. 6 API endpoints: `GET/POST /api/v1/address-lists`, `GET /{name}`, `DELETE /entry/{id}`, `POST /{name}/flush`
- **Connection State Matching (5.2):** `src/firewall/conn_state.rs` — `ConnectionState` enum (New/Established/Related/Invalid/Untracked) + `ConnStateFilter` with invert support
- **Tools (5.3):** `src/tools/` — `Pinger::ping()` via OS `ping` command, `traceroute()` via `tracert`/`traceroute`. Cross-platform parsers (Windows + Linux). 2 API endpoints: `GET /api/v1/tools/ping`, `GET /api/v1/tools/traceroute`
- **DHCP Client (5.4):** `src/dhcp_client/` — `DhcpClientBackend` trait + `MockDhcpClient` + `DhcpClientManager`. DORA lifecycle (discover, request, renew, release). 3 API endpoints: `POST /{iface}/discover`, `GET /{iface}/status`, `POST /{iface}/release`
- **Scheduler (5.5):** `src/scheduler/` — `ScheduledTask` with `ScheduleInterval` (Once, Every, Daily, Weekly, Cron), `ScheduledTaskAction` (HTTP get/post, CLI command, enable/disable interface, cleanup). 5 API endpoints: `GET/POST /api/v1/scheduler/tasks`, `GET/DELETE /{id}`, `POST /{id}/toggle`

### Added (Sprint 2 — Connectivity)

- **BGP Real Backend (5.6):** `src/routing/bgp_real.rs` — BGP message codec (OPEN/UPDATE/KEEPALIVE/NOTIFICATION), TCP socket session per peer (port 179), FSM (Idle→Connect→OpenSent→OpenConfirm→Established), `#[cfg(feature = "real")]`
- **OSPF Real Backend (5.7):** `src/routing/ospf_real.rs` — OSPF HELLO packet encode/decode, multicast via UDP socket (224.0.0.5:89), area state management, `#[cfg(feature = "real")]`
- **Route Filters (5.8):** `src/routing/filters.rs` — PrefixList entry with ge/le matching, AS-Path exact/regex/any filter, RouteMap entry with set actions (local-pref, metric, as-path-prepend, next-hop, community, tag). 12 API endpoints: prefix-lists CRUD, as-path CRUD, route-maps CRUD
- **WireGuard Real Backend (5.9):** `src/wireguard/real.rs` — Interface create/delete via `ip link add dev wg0 type wireguard`, keypair via `wg genkey` stdin pipe, peer management via `wg set`, `#[cfg(feature = "real")]`
- **Bonding/LACP (5.10):** `src/bonding/` — `BondMode` (RoundRobin, ActiveBackup, XOR, Broadcast, Ieee8023ad, Tlb, Alb), `BondingBackend` trait + `MockBondingBackend` + `BondingManager`. 7 API endpoints: bond CRUD, slave add/remove, status
- **Bridge VLAN Filtering (5.11):** `src/net/bridge_vlan.rs` — `BridgeVlanManager` with access/trunk mode, tagged/untagged VLAN lists, PVID support. 5 API endpoints: GET/POST /api/v1/bridge-vlan, GET /{bridge}, DELETE /{bridge}/{port}/{vlan}

### Added (Infrastructure)

- 23 new API endpoints across 6 new modules (total API endpoints: 80+)
- 6 new manager structs added to `AppState`
- `RoutingProtocol::Connected` variant added

### Fixed

- `add_route` handler missing closing braces (pre-existing brace mismatch in handlers.rs)
- Tracert/Traceroute parser: skip TTL column when searching for RTT values (was picking up hop number as RTT)
- Address list expiry: changed from integer-second comparison to f64 subsecond precision
- WireGuard real backend: removed unused `rand`, `x25519_dalek`, `base64` deps; keygen via `wg genkey` CLI pipe instead
- BGP real backend: `octets()` on `IpAddr` → match to concrete `Ipv4Addr`/`Ipv6Addr`
- OSPF real backend: removed unused imports (`HashMap`, `Arc`, `Duration`, `OSPF_PORT`, `OSPF_DBD`)
- Route filter API: cleaned up moved-ownership warning in `name` variable

## [0.4.0] - 2026-05-30

### Added

- **Web UI (3.2):** 12-page dashboard with Tera templates + HTMX + Alpine.js — interfaces, firewall, NAT, routes, QoS, users, packages, sessions, DHCP, DNS, monitoring, billing
- **SSE Monitoring (3.3-3.4):** Real-time bandwidth/CPU/conntrack stream via Server-Sent Events (`/api/v1/monitoring/stream`)
- **Conntrack Analyzer (3.5):** `top_talkers()`, `protocol_distribution()` analysis methods
- **Billing API (3.6):** BillingBackend trait, BillingPlan, Invoice management, web UI page
- **Dynamic Routing (4.1):** BGP peer management + OSPF area management via DynamicRouting trait + MockDynamicRouting, 8 API endpoints
- **WireGuard Manager (4.2):** WireguardBackend trait + MockWireguardBackend, 7 API endpoints, web UI with Alpine.js fetch CRUD
- **VRRP (4.3):** VrrpBackend trait, VrrpInstance management, API + web UI
- **PPPoE Failover (4.4):** PppFailoverBackend trait, uplink priority failover, trigger API, web UI
- **BPF+EDT QoS (4.5):** BpfQosBackend trait, BpfQosManager with high-performance qdisc attachment API
- **Plugin System (4.6):** Plugin trait + PluginRegistry with load/enable/disable lifecycle, tokio::sync::RwLock
- **Multi-tenancy (4.7):** TenancyBackend trait, Tenant CRUD API
- **RADIUS Encryption:** RFC 2865 Section 5.2 MD5 XOR password encryption via `md-5` crate
- **NAT Listing:** RealBackend `list_rules()` via nftables netlink dump, comment-based masquerade detection, expression bytes parsing for `to_addr`/`to_port`
- **RealPppoeBackend:** Full AF_PACKET raw socket implementation (libc::socket, bind, sendto, recvfrom)
- **InterfaceKind:** `Dummy`, `Bridge`, `Vlan { parent, vlan_id }` enum added to `InterfaceConfig`
- **Argon2 Password Hashing:** SHA-256 → Argon2 (PHC string format, salt otomatis)
- **Competitor Benchmarks:** `benches/routing.rs` with HashMap/vec baselines vs MockDynamicRouting
- **Debug Implementations:** `fmt::Debug` added to all 6 manager structs (InterfaceManager, FirewallManager, QosManager, ConntrackManager, RouterManager, NatManager)
- **Doc Comments:** Added to all `pub` items in `api/mod.rs`, `traits/netlink.rs`, and key public types
- **SRI Hashes:** CDN scripts (Tailwind, HTMX, Alpine.js) now include `integrity` attributes
- **CPU Delta Monitoring:** CPU calculation uses delta between readings via `AtomicU64` statics

### Changed

- **Password Storage:** `User.password` → `User.password_hash` with `set_password()`/`verify_password()` methods
- **API Module Split:** `src/api/mod.rs` split into `mod.rs` + `handlers.rs` + `monitoring.rs` (956→200 lines)
- **`unsafe_code` lint:** Changed from `#![deny(unsafe_code)]` to `#![cfg_attr(not(feature = "real"), deny(unsafe_code))]` to allow raw socket FFI
- **Conntrack hashsize:** `set_buckets()` now tries sysctl write (non-fatal warning on failure)
- **IPv6 NAT:** Changed from `bail!()` to `tracing::warn()` + skip
- **`libc` crate:** Made optional (`real` feature only)

### Fixed

- **LCP Option Encoding:** `encode()` was writing `opt.value.len()` instead of `opt.value.len() + 2` (total length) — fixed
- **Template Path Resolution:** Binary-relative path now also checks grandparent directory
- **WireGuard Template:** Python-style `[:16]` slice syntax → Tera `truncate` filter
- **CDN Redirect Issue:** `cdn.tailwindcss.com` 302 redirect caused SRI mismatch — switched to direct versioned URL
- **VlanLink API:** `.vlan_id()` method doesn't exist — `VlanLink::new()` takes 3 args directly
- **`str_as_str` unstable:** Rust 1.96 unstable feature — changed to `as_ref()`
- **RADIUS Integration Tests:** Missing `"secret"` param in `RadiusClient::new()` calls
- **Various clippy warnings:** `manual_div_ceil`, `sort_by_key`, `redundant_closure`, `new_without_default`, `comparison_chain`
- **`futures` dependency:** Was accidentally removed during dependency cleanup — restored

## [0.3.0] - 2026-05-29

### Added

- **Real Backend (1.1b):** nlink-based `RealBackend` implementing all 6 core traits (NetlinkIfaces, Firewall, QoS, Conntrack, NAT, Route) — `cargo build --features real`
- **REST API (3.1):** Axum HTTP server with 25 endpoints for all resources — interfaces, firewall, NAT, routes, QoS, conntrack, users, packages — `cargo run --features api`
- `Interface`, `FirewallRule`, `NatRule`, `Route` etc. now implement `Serialize` for JSON output
- `serde_json` dependency for API response serialization

### Fixed

- `#[derive(Serialize)]` added to all major trait types for JSON API support

## [0.2.0] - 2026-05-29

### Added

- **PPPoE Discovery (2.1):** Full PADI/PADO/PADR/PADS/PADT state machine, packet encoding/decoding (RFC 2516), PppoeBackend trait + mock, client and server implementations
- **PPP Negotiation (2.2):** LCP (Config/Ack/Nak/Reject/Terminate/Echo), PAP and CHAP authentication, IPCP negotiation, PppNegotiation client/server with full state machine
- **Session Management (2.3):** PppSession lifecycle handling, start/process/queue frame management
- **RADIUS Client (2.4):** RadiusAttribute + RadiusPacket (RFC 2865/2866), MockRadiusBackend, RadiusClient (auth + accounting start/stop/interim), RadiusSessionManager
- **User Management (2.5):** User CRUD, UserPackage with bandwidth profiles, UserBackend trait + MockUserBackend, UserManager with IP/MAC binding and authentication
- **DHCP Server (2.6):** DHCP packet (DORA), IpPool management, lease tracking with expiry, reserved IPs, Discover→Offer→Request→Ack state machine
- **DNS Forwarder (2.7):** DNS packet encode/decode (RFC 1035), in-memory cache with TTL eviction, adblock domain blacklist with wildcard support, localhost resolution
- **Bandwidth via RADIUS (2.8):** Parsing MikroTik Rate-Limit from Filter-ID attributes, WISPr bandwidth attributes, BandwidthProfile conversion
- **Integration Tests (2.9):** 9 new tests covering PPPoE+RADIUS+User end-to-end, multi-session, LCP+PAP integration
- **Benchmarks (2.10):** 6 new criterion benchmarks for PPPoE discovery, RADIUS auth, DHCP DORA, user CRUD, LCP negotiation, bandwidth parsing

### Fixed

- `FirewallRule.positions` → `position` (typo)
- `PppoeServer::process_one()` now logs recv errors via `tracing::warn!`
- `ConfigEngine::load_or_default()` now attempts binary fallback when YAML is corrupted
- `DiscoveryState` visibility changed to `pub`
- Integration tests import cleanup

## [0.1.0] - 2026-05-28

### Added

- Core traits: `NetlinkIfaces`, `NetlinkFirewall`, `NetlinkQos`, `NetlinkConntrack`, `NetlinkNat`, `NetlinkRoute` with mock backend
- Interface manager: list, get, create, delete, up/down, MTU validation, VLAN (1-4094), bridge, address management
- Firewall manager: zone-based model with rule add/delete/flush, default zones (lan/wan/vpn)
- QoS manager: HTB root qdisc, per-user class, fq_codel leaf, rate/ceil validation
- Conntrack manager: max/bucket tuning with bounds validation (1024-4M), usage ratio, fast-track
- NAT manager: SNAT, DNAT, masquerade helpers
- Route manager: prefix validation (<=128), default route helper
- Config engine: YAML schema to bincode serialization, transactional commit/rollback with backup
- CLI framework: clap subcommands (interface, firewall, qos, config) + ratatui TUI with 6 screens
- Integration tests: 7 tests covering full multi-manager scenarios
- Benchmarks: 6 criterion benchmarks for mock backend operations
- PPPoE stub: structure for Phase 2 with auth, discovery, session modules
