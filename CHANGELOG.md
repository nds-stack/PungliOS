# Changelog

All notable changes to PungliOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-05-29

### Added

- **PPPoE Discovery (2.1):** Full PADI/PADO/PADR/PADS/PADT state machine, packet encoding/decoding (RFC 2516), PppoeBackend trait + mock, client and server implementations
- **PPP Negotiation (2.2):** LCP (Config/Ack/Nak/Reject/Terminate/Echo), PAP and CHAP authentication, IPCP negotiation, PppNegotiation client/server with full state machine
- **Session Management (2.3):** PppSession lifecycle handling, start/process/queue frame management
- **RADIUS Client (2.4):** RadiusAttribute + RadiusPacket (RFC 2865/2866), MockRadiusBackend, RadiusClient (auth + accounting start/stop/interim), RadiusSessionManager
- **User Management (2.5):** User CRUD, UserPackage with bandwidth profiles, UserBackend trait + MockUserBackend, UserManager with IP/MAC binding and authentication
- **DHCP Server (2.6):** DHCP packet (DORA), IpPool management, lease tracking with expiry, reserved IPs, Discover→Offer→Request→Ack state machine
- **Bandwidth via RADIUS (2.8):** Parsing MikroTik Rate-Limit from Filter-ID attributes, WISPr bandwidth attributes, BandwidthProfile conversion
- **Integration Tests (2.9):** 9 new tests covering PPPoE+RADIUS+User end-to-end, multi-session, LCP+PAP integration

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
