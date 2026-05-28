# TODO.md — PungliOS Roadmap & Milestones

> Status: 🟢 Phase 1 Complete | 🟢 Phase 2 Complete | 🟡 Phase 3.1 Done (3.2-3.8 TODO)

---

## Phase 1: Core Infrastructure (MVP)

**Target:** Single box bisa jadi router dengan QoS per-user
**Status:** 🟢 **COMPLETE**

| # | Task | Komponen | Depends On | Status | Priority |
|---|------|----------|------------|--------|----------|
| 1.1 | Setup project structure (`cargo init`, folder layout) | Foundation | — | 🟢 DONE | P0 |
| 1.1a | Core traits (`NetlinkIfaces`, `NetlinkFirewall`, `NetlinkQos`) + mock backend (in-memory) | Test Infra | 1.1 | 🟢 DONE | P0 |
| 1.1b | Real backend (`nlink` integration — 6 traits implemented) | Test Infra | 1.1a | 🟢 DONE | P1 |
| 1.2 | Interface manager (add/delete/list, VLAN, bridges via traits) | Networking | 1.1a | 🟢 DONE | P0 |
| 1.3 | nftables wrapper (zone-based model via traits) | Firewall | 1.1a, 1.2 | 🟢 DONE | P0 |
| 1.4 | tc QoS engine (HTB + fq_codel, per-user class via traits) | QoS | 1.1a, 1.2 | 🟢 DONE | P1 |
| 1.5 | Conntrack manager (auto-tuning, fast-track via traits) | Performance | 1.1a, 1.2 | 🟢 DONE | P1 |
| 1.6 | Config engine (YAML → bincode, transactional commit/rollback) | Config Engine | 1.2-1.5 | 🟢 DONE | P0 |
| 1.7 | CLI framework (clap + ratatui interactive shell) | CLI | 1.2-1.6 | 🟢 DONE | P0 |
| 1.8 | NAT manager (SNAT, DNAT, masquerade via traits) | NAT | 1.1a, 1.3 | 🟢 DONE | P2 |
| 1.9 | Static routing (route table via traits) | Routing | 1.1a, 1.2 | 🟢 DONE | P2 |
| 1.10 | Integration tests (Phase 1 features, use mock backend) | Testing | 1.2-1.9 | 🟢 DONE | P0 |
| 1.11 | Benchmarks (Phase 1 components, mock backend) | Performance | 1.2-1.9 | 🟢 DONE | P1 |
| 1.12 | README + API docs (Phase 1) | Documentation | 1.2-1.9 | 🟢 DONE | P1 |

**Success Metrics:**
- [ ] 100+ concurrent users
- [ ] 1 Gbps throughput
- [ ] CPU <50% @ max load
- [ ] Config reload <1s

---

## Phase 2: PPPoE + Authentication

**Target:** Handle 10K+ PPPoE sessions dengan RADIUS
**Status:** 🟢 **COMPLETE**

| # | Task | Komponen | Status | Priority |
|---|------|----------|--------|----------|
| 2.1 | PPPoE discovery (PADI/PADO/PADR/PADS/PADT) | PPPoE | 🟢 DONE | P0 |
| 2.2 | PPP negotiation (LCP, IPCP, auth: PAP/CHAP/MS-CHAPv2) | PPPoE | 🟢 DONE | P0 |
| 2.3 | Session management (kernel-mode pppX interfaces) | PPPoE | 🟢 DONE | P0 |
| 2.4 | RADIUS client (auth + accounting + CoA) | RADIUS | 🟢 DONE | P0 |
| 2.5 | User management (CRUD, group/paket, bandwidth profile) | User Mgmt | 🟢 DONE | P1 |
| 2.6 | DHCP server (DORA, IP pool, lease mgmt) | DHCP | 🟢 DONE | P1 |
| 2.7 | DNS forwarder (cache + adblock) | DNS | 🟢 DONE | P2 |
| 2.8 | Per-user bandwidth via RADIUS attributes | QoS | 🟢 DONE | P1 |
| 2.9 | Integration tests (Phase 2 features) | Testing | 🟢 DONE | P0 |
| 2.10 | Benchmarks (PPPoE session scale) | Performance | 🟢 DONE | P1 |

**Success Metrics:**
- [ ] 10K+ concurrent PPPoE sessions
- [ ] 5 Gbps throughput
- [ ] CPU <60% @ max load

---

## Phase 3: Management + Monitoring

**Target:** Web UI, REST API, real-time monitoring
**Deadline:** TBD

| # | Task | Komponen | Status | Priority |
|---|------|----------|--------|----------|
| 3.1 | REST API (Axum, full CRUD semua resource) | API | 🟢 DONE | P0 |
| 3.2 | Web UI dashboard (Leptos/Yew) | Web UI | 🔴 TODO | P1 |
| 3.3 | Real-time bandwidth monitoring | Monitoring | 🔴 TODO | P1 |
| 3.4 | CPU & conntrack monitoring | Monitoring | 🔴 TODO | P1 |
| 3.5 | Connection tracking analyzer | Monitoring | 🔴 TODO | P2 |
| 3.6 | Billing integration API | Billing | 🔴 TODO | P2 |
| 3.7 | User management dashboard | Web UI | 🔴 TODO | P2 |
| 3.8 | QoS config UI | Web UI | 🔴 TODO | P2 |

**Success Metrics:**
- [ ] REST API response <50ms
- [ ] Real-time dashboard refresh <1s

---

## Phase 4: Advanced Features

**Target:** Enterprise-grade
**Deadline:** TBD

| # | Task | Komponen | Status | Priority |
|---|------|----------|--------|----------|
| 4.1 | Dynamic routing (BGP/OSPF via FRR atau Rust-native) | Routing | 🔴 TODO | P1 |
| 4.2 | WireGuard manager | VPN | 🔴 TODO | P1 |
| 4.3 | VRRP (high availability) | HA | 🔴 TODO | P2 |
| 4.4 | Redundant PPPoE failover | HA | 🔴 TODO | P2 |
| 4.5 | BPF+EDT QoS engine (high-performance >10Gbps) | QoS | 🔴 TODO | P2 |
| 4.6 | Plugin system (extensibility framework) | Plugins | 🔴 TODO | P3 |
| 4.7 | Multi-tenancy | Platform | 🔴 TODO | P3 |

**Success Metrics:**
- [ ] 50K+ concurrent users
- [ ] 10+ Gbps throughput
- [ ] CPU <70% @ max load
- [ ] HA failover <100ms

---

## Future (Post-P4)

| Task | Status | Notes |
|------|--------|-------|
| DPDK/VPP data plane (100Gbps+) | 🔵 Backlog | |
| Kubernetes operator | 🔵 Backlog | |
| Cloud-native deployment | 🔵 Backlog | |
| RESTCONF/YANG API | 🔵 Backlog | |

---

## Legend

| Status | Arti |
|--------|------|
| 🔴 TODO | Belum dimulai |
| 🟡 WIP | Sedang dikerjakan |
| 🟢 DONE | Selesai |
| 🔵 Backlog | Ditunda |
| ⚫ Cancelled | Dibatalkan |

| Priority | Arti |
|----------|------|
| P0 | Blocking — must do first |
| P1 | High — important |
| P2 | Medium — nice to have |
| P3 | Low — future nice to have |

---

## Dependency Graph (Phase 1)

```
Foundation (1.1)
     │
     ├──▶ Core Traits + Mock Backend (1.1a) ◀══ P0 — enable testing everywhere
     │         │
     │         ├──▶ Real Backend (1.1b) ── nftnl + nlink (production only)
     │         │
     │         ├──▶ Interface Manager (1.2) ──────────────────────┐
     │         │      │                                            │
     │         │      ├──▶ nftables Wrapper (1.3) ──▶ NAT (1.8)  │
     │         │      │                                            │
     │         │      ├──▶ tc QoS Engine (1.4)                     │
     │         │      │                                            │
     │         │      ├──▶ Conntrack Manager (1.5)                 │
     │         │      │                                            │
     │         │      └──▶ Static Routing (1.9)                    │
     │         │               │                                    │
     │         └───────────────┴──▶ Config Engine (1.6) ◀──────────┘
     │                                    │
     │                                    ▼
     │                               CLI (1.7)
     │                                    │
     └────────────────────────────────────┴──▶ Tests + Benchmarks (1.10, 1.11)
```
**Key:** Mock backend (1.1a) makes all components testable on Windows/CI without Linux kernel.

---

## Next Actions — Phase 1

1. [x] **1.1** Setup project structure
2. [x] **1.1a** Core traits + mock backend
3. [x] **1.2** Interface manager
4. [x] **1.3** nftables wrapper
5. [x] **1.4** tc QoS engine
6. [x] **1.5** Conntrack manager
7. [x] **1.6** Config engine
8. [x] **1.7** CLI
9. [x] **1.8** NAT manager
10. [x] **1.9** Static routing
11. [x] **1.10** Integration tests
12. [x] **1.11** Benchmarks
13. [x] **1.12** README + API docs

## Next Actions — Phase 2

1. [x] **2.1** PPPoE discovery — packet encode/decode, PADI/PADO/PADR/PADS/PADT state machine
2. [x] **2.2** PPP negotiation — LCP, PAP, CHAP, IPCP
3. [x] **2.3** Session management — PppSession lifecycle
4. [x] **2.4** RADIUS client — auth + accounting
5. [x] **2.5** User management — CRUD, packages, bandwidth profiles
6. [x] **2.6** DHCP server — DORA, IP pool, lease management
7. [x] **2.7** DNS forwarder — cache + adblock
8. [x] **2.8** Per-user bandwidth via RADIUS
9. [x] **2.9** Integration tests
10. [x] **2.10** Benchmarks

---

*Last updated: 2026-05-29*
