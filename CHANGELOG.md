# Changelog

All notable changes to PungliOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
