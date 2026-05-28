# PungliOS — Product Requirements Document (PRD)

> Rust-Native ISP/WISP Management Platform

---

## 1. Overview

| Field | Value |
|-------|-------|
| **Nama** | PungliOS |
| **Tagline** | Rust-Native ISP/WISP Management Platform |
| **Goal** | Platform manajemen jaringan ISP/WISP berperforma tinggi, handle puluhan ribu user dengan QoS fleksibel, CPU tetap rendah |
| **Language** | Rust (full control, no C dependencies kecuali kernel interface) |
| **Target** | Lab testing → Production |
| **Inspirasi** | OpenWrt-level fleksibilitas, MikroTik-level fitur, Rust-level performa |

---

## 2. Problem Statement

| Problem | Saat Ini (MikroTik) | Target PungliOS |
|---------|---------------------|-----------------|
| CPU spike saat connection tracking overload | Connection tracking 100K limit, CPU spike setelah 50K | Auto-tuning, fast-track otomatis, handle jutaan connection |
| QoS manual, gak ada visibility | Rule ordering static, user harus manual optimasi | Real-time monitoring + auto-optimization, visibility rule mana yang makan CPU |
| Hardware mahal (RouterOS license) | MikroTik RB750Gr3 Rp500rb+ | x86 biasa (PC bekas, N100, RPi 5) |
| Feature lock-in proprietary | Tidak open source | Open source, full control |
| PPPoE session limit | ~8K stable di x86 | 10K-50K+ sessions |
| Fast-track perlu manual enable | Manual | Otomatis |

---

## 3. Target Users

| Tier | Hardware | Users | Throughput | Use Case |
|------|----------|-------|------------|----------|
| 🏡 Home/Lab | RPi 5, Orange Pi 5 | <1K | <1 Gbps | Lab testing, home network |
| 🏢 Small WISP | x86 N100/Celeron mini PC | 1K-5K | 1-5 Gbps | WISP kecil, kafe, hotspot |
| 🏭 Medium ISP | x86 Xeon/Epyc server | 5K-20K | 5-10 Gbps | ISP regional |
| 🏢 Large ISP | Clustered x86 + XDP | 20K-50K+ | 10-50+ Gbps | ISP besar, carrier-grade |

---

## 4. Architecture

### 4.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────┐
│              Management Plane (Rust)                 │
│  CLI │ REST API │ Web UI │ Billing API              │
├─────────────────────────────────────────────────────┤
│              Control Plane (Rust)                    │
│  Config Engine │ PPPoE Server │ RADIUS Client       │
│  DHCP │ DNS │ NAT Manager │ QoS Policy Engine      │
├─────────────────────────────────────────────────────┤
│              Data Plane (Rust + eBPF/nftables)      │
│  nftables (firewall/NAT) │ tc HTB+fq_codel (QoS)   │
│  PPPoE kernel mode │ conntrack tuning               │
├─────────────────────────────────────────────────────┤
│              Linux Kernel                           │
│  Netfilter │ tc │ eBPF │ NIC multiqueue             │
└─────────────────────────────────────────────────────┘
```

### 4.2 Target Topology

```
ONT ISP ──▶ PungliOS Box ──▶ Distribusi ke banyak router/ONT
                                │
                                ├── PPPoE Server (10K+ sessions)
                                ├── QoS Engine (per-user HTB)
                                ├── Firewall (nftables)
                                ├── NAT Manager
                                └── Monitoring Dashboard
```

### 4.3 Key Design Principles

1. **No Kernel Bypass (Phase 1-3):** Gunakan Linux kernel + nftables/tc, control plane Rust
2. **Modular Architecture:** Setiap komponen bisa di-develop dan test secara independen
3. **Config-Driven:** Semua konfigurasi dari file, bukan hardcode
4. **Auto-Tuning:** Conntrack, fast-track, rule optimization otomatis
5. **Dual-Format Config:** Human-readable (YAML) untuk operator, binary (rkyv) untuk runtime

---

## 5. Config Strategy (Dual-Format)

### 5.1 Format Selection

| Layer | Format | Alasan | Performance |
|-------|--------|--------|-------------|
| Human (operator/CLI) | YAML | Readable, comment support | 46 MB/s parse |
| Startup load | rkyv | Zero-copy, ~instant access | ~1.4 ns (pointer cast) |
| Hot reload | Protobuf delta | Schema evolution, streaming | ~5 ms/MB |
| Internal IPC | Protobuf + tonic (gRPC) | Standard networking | - |
| Backup/export | Bincode | Compact, fast serialize | ~1 ms/MB |

### 5.2 Performance Comparison

| Format | Parse Speed (1MB) | Size vs JSON | Human-Readable |
|--------|-------------------|--------------|----------------|
| rkyv | ~1.4 ns | 72% | Tidak |
| Bincode | ~1 ms/MB | 73% | Tidak |
| Protobuf | ~5 ms/MB | 45-75% | Tidak |
| JSON | ~55 ms/MB | Baseline | Ya |
| YAML | ~340 ms/MB | 85% | Ya |
| TOML | ~460 ms/MB | ~100% | Ya |

### 5.3 Config Model

```yaml
# Contoh: PungliOS config (YAML)
version: "1.0"
interfaces:
  - name: eth0
    role: wan
    addresses:
      - dhcp
  - name: eth1
    role: lan
    addresses:
      - 192.168.1.1/24

pppoe:
  enabled: true
  interface: eth1
  max-sessions: 50000
  authentication:
    method: radius
    servers:
      - host: 10.0.0.100
        port: 1812
        secret: "${RADIUS_SECRET}"

qos:
  enabled: true
  default-class: basic-10mb
  classes:
    - name: basic-10mb
      upload: 10mbit
      download: 10mbit
      priority: 3
    - name: premium-50mb
      upload: 50mbit
      download: 50mbit
      priority: 1

firewall:
  zones:
    - name: wan
      interfaces: [eth0]
    - name: lan
      interfaces: [eth1]
  rules:
    - name: allow-ssh
      zone: lan
      protocol: tcp
      port: 22
      action: accept
```

---

## 6. Phased Development Plan

### Phase 1: Core Infrastructure (MVP)

**Target:** Single box bisa jadi router dengan QoS per-user

| Komponen | Detail | Estimasi | Status |
|----------|--------|----------|--------|
| **nftables wrapper** | Rust bindings via netlink, zone-based firewall model | 2-3 minggu | TODO |
| **tc QoS engine** | HTB + fq_codel, per-user class creation, auto-tuning | 2-3 minggu | TODO |
| **Config engine** | YAML → rkyv, transactional commit/rollback | 1-2 minggu | TODO |
| **CLI** | Basic router commands (interface, firewall, qos) | 1-2 minggu | TODO |
| **Conntrack manager** | Auto-tuning, fast-track optimization | 1 minggu | TODO |

**Deliverable:**
- Binary `pungli` yang bisa manage interfaces, VLAN, bridges
- Generate nftables rules dari config
- Setup HTB QoS per-user
- Auto-optimize conntrack dan fast-track

**Success Metrics:**
- 100+ concurrent users
- 1 Gbps throughput
- CPU <50% @ max load
- Config reload <1s

### Phase 2: PPPoE + Authentication

**Target:** Handle 10K+ PPPoE sessions dengan RADIUS

| Komponen | Detail | Estimasi | Status |
|----------|--------|----------|--------|
| **PPPoE server** | Rust-native, kernel-mode data path | 4-6 minggu | TODO |
| **RADIUS client** | Auth + Accounting + CoA (Change of Authorization) | 2 minggu | TODO |
| **User management** | CRUD users, group/paket management | 2 minggu | TODO |
| **DHCP server** | Rust-native atau integrate | 1-2 minggu | TODO |
| **DNS forwarder** | Cache + adblock | 1 minggu | TODO |

**Deliverable:**
- PPPoE server handle 10K+ sessions
- MS-CHAPv2/PAP auth via RADIUS
- Per-user bandwidth limiting dari RADIUS attributes
- Accounting (session time, bandwidth usage)
- CoA untuk real-time bandwidth change

**Success Metrics:**
- 10K+ concurrent PPPoE sessions
- 5 Gbps throughput
- CPU <60% @ max load

### Phase 3: Management + Monitoring

**Target:** Web UI, REST API, real-time monitoring

| Komponen | Detail | Estimasi | Status |
|----------|--------|----------|--------|
| **REST API** | Full CRUD semua resource | 2 minggu | TODO |
| **Web UI** | Dashboard, user mgmt, QoS config | 3-4 minggu | TODO |
| **Monitoring** | Real-time bandwidth, CPU, conntrack | 2 minggu | TODO |
| **Billing integration** | API untuk billing system external | 1-2 minggu | TODO |

**Deliverable:**
- REST API untuk semua operasi
- Web dashboard real-time
- Export accounting data

### Phase 4: Advanced Features

**Target:** Enterprise-grade

| Komponen | Detail | Estimasi | Status |
|----------|--------|----------|--------|
| **Dynamic routing** | BGP/OSPF via FRR atau Rust-native | 4-6 minggu | TODO |
| **VPN** | WireGuard manager | 1-2 minggu | TODO |
| **HA/Failover** | VRRP, redundant PPPoE | 2-3 minggu | TODO |
| **Plugin system** | Extensibility framework | 2 minggu | TODO |
| **BPF+EDT QoS** | High-performance >10Gbps | 3-4 minggu | TODO |

---

## 7. Key Technical Decisions

### 7.1 QoS Strategy

| Phase | Approach | Alasan |
|-------|----------|--------|
| Phase 1-3 | HTB + fq_codel | Proven at 10K+ scale, simpler |
| Phase 4 | BPF+EDT | Best performance, no lock bottleneck |

**HTB Limitations:**
- Single global qdisc lock → max ~8-11 Gbps
- 10K+ classes = OK dengan u32 hashing
- CPU bottleneck di lock contention, bukan class count

**BPF+EDT Advantages:**
- No global lock (per-CPU atomic operations)
- 20x improvement in p95 latency (Google benchmark)
- Eliminates lock contention entirely

### 7.2 PPPoE Approach

| Decision | Choice | Alasan |
|----------|--------|--------|
| Data path | Kernel-mode | Performance (avoid context switch) |
| Control plane | Rust-native | Full control, memory safe |
| Auth | RADIUS (FreeRADIUS compatible) | Industry standard |
| Session limit target | 50K+ | Carrier-grade |

**Rust PPPoE Components:**
- PPPoE discovery (PADI/PADO/PADR/PADS/PADT)
- PPP negotiation (LCP, IPCP, authentication)
- Session management
- Kernel interface creation (pppX)

### 7.3 Conntrack Tuning

| Parameter | Value | Alasan |
|-----------|-------|--------|
| `nf_conntrack_max` | 2,097,152 (2M) | Sweet spot untuk ISP workload |
| `nf_conntrack_buckets` | 524,288 (512K) | 1/4 dari max untuk O(1) lookup |
| `tcp_timeout_established` | 3600s | Reduce churn |
| `tcp_timeout_time_wait` | 30s | Fast cleanup |
| Fast-track | Auto | Bypass conntrack untuk high-volume |

### 7.4 Firewall Model

- **Zone-based** (seperti OpenWrt/IPFire)
- Zones: wan, lan, dmz, guest, custom
- Inter-zone policies
- Rules generated dari abstract model

---

## 8. Tech Stack

| Component | Technology | Alasan |
|-----------|-----------|--------|
| **Language** | Rust | Memory safety + performa |
| **Async runtime** | Tokio | Industry standard Rust async |
| **CLI** | clap + ratatui | Powerful CLI framework |
| **Web UI** | Leptos atau Yew | Rust-native frontend |
| **IPC** | tonic (gRPC) | Standard networking |
| **nftables** | nftnl | Safe nftables bindings (Mullvad, 730K downloads) |
| **tc** | nlink | Async tc netlink |
| **eBPF** | Aya | Pure Rust eBPF |
| **Config (human)** | serde_yaml | Readable |
| **Config (binary)** | rkyv | Zero-copy |
| **Config (IPC)** | prost (protobuf) | gRPC ecosystem |
| **Database** | SQLite (small) / PostgreSQL (large) | Flexibility |
| **Cache** | Redis | RADIUS auth cache |

### 8.1 Key Rust Crates

```toml
[dependencies]
# Async
tokio = { version = "1", features = ["full"] }
tonic = "0.8"
prost = "0.12"

# CLI
clap = { version = "4", features = ["derive"] }
ratatui = "0.25"

# Config
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
rkyv = { version = "0.7", features = ["validation"] }

# Networking
nftnl = "0.9"        # nftables (Mullvad, libnftnl safe abstraction)
nlink = "0.11"        # tc
aya = "0.12"          # eBPF
pnet = "0.34"         # packet manipulation

# Database
sqlx = { version = "0.7", features = ["runtime-tokio", "sqlite", "postgres"] }

# Monitoring
tracing = "0.1"
metrics = "0.21"
```

---

## 9. Research Findings

### 9.1 Linux tc/QoS at Scale

| Metric | Value | Source |
|--------|-------|--------|
| HTB max classes | ~65,536 per major handle | Kernel docs |
| HTB single lock bottleneck | ~8-11 Gbps | Netdev 0x14 |
| HTB + u32 hashing | 10K+ classes OK | LARTC mailing list |
| CAKE vs HTB CPU | CAKE higher CPU | Lucid.net benchmark |
| BPF+EDT vs HTB | 20x p95 improvement | Google (Netdev 0x14) |

### 9.2 nftables vs iptables

| Ruleset Size | nftables Advantage | Source |
|--------------|-------------------|--------|
| <100 rules | Similar | Didi L benchmark |
| ~1K rules | nftables 10-25% better | Didi L benchmark |
| >10K rules | nftables 2-4x PPS ceiling | Didi L benchmark |
| 50K deny IPs | nftables 2.8x PPS | Didi L benchmark |

### 9.3 Connection Tracking

| Config | Practical Limit | Memory | Source |
|--------|----------------|--------|--------|
| Default | 128K-262K | ~100-150 MB | Most distros |
| Tuned | 1M | ~400-600 MB | Cribl |
| Aggressive | 4M | ~1.5-2.5 GB | Large deployments |
| Sweet spot | 2M | ~800 MB | ISP/gateway |

### 9.4 PPPoE Server Comparison

| Solution | Max Sessions | Architecture | Open Source |
|----------|-------------|--------------|-------------|
| Accel-PPP | 16K+ | Multi-threaded, kernel-mode | Yes |
| RP-PPPoE | ~1K | Process-per-session | Yes |
| MikroTik | 5K-8K stable | Proprietary | No |
| VPP/DPDK BNG | 100K+ | Userspace | Yes |

### 9.5 Existing Rust Networking Projects

| Project | Relevance | Stars |
|---------|-----------|-------|
| LibreQoS | Rust-based ISP QoS | - |
| Maghemite | Rust routing stack (BGP/BFD) | 87 |
| Aya | Rust eBPF | - |
| nftnl | nftables bindings (Mullvad) | 730K+ downloads |
| nlink | tc netlink | - |

---

## 10. Success Metrics

### 10.1 Per-Phase Metrics

| Metric | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|
| Concurrent users | 100+ | 10K+ | 10K+ | 50K+ |
| Throughput | 1 Gbps | 5 Gbps | 5 Gbps | 10+ Gbps |
| CPU @ max load | <50% | <60% | <60% | <70% |
| Config reload | <1s | <1s | <1s | <100ms |
| PPPoE sessions | N/A | 10K+ | 10K+ | 50K+ |
| Memory usage | <512 MB | <2 GB | <2 GB | <4 GB |

### 10.2 Comparison vs MikroTik

| Feature | MikroTik RB750Gr3 | PungliOS (Target) |
|---------|-------------------|-------------------|
| Price | Rp500K+ (hardware + license) | Hardware only (RPi5 Rp700K) |
| PPPoE sessions | ~8K stable | 50K+ |
| Throughput | 6-7 Gbps | 10+ Gbps |
| CPU @ max | 100% spike | <70% stable |
| QoS | Manual | Auto-tuning |
| Open source | No | Yes |

---

## 11. Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rust PPPoE bugs | High | Start with Accel-PPP integration, migrate to Rust-native |
| tc lock bottleneck | Medium | Use u32 hashing, Phase 4 BPF+EDT |
| Config complexity | Medium | Dual-format, transactional rollback |
| Memory leak | High | Rust ownership + fuzzing |
| Kernel compatibility | Medium | Test on multiple kernel versions |

---

## 12. Future Roadmap

| Phase | Features | Timeline |
|-------|----------|----------|
| Phase 5 | Dynamic routing (BGP), HA/failover, plugin system | TBD |
| Phase 6 | DPDK/VPP data plane, 100Gbps+ | TBD |
| Phase 7 | Kubernetes operator, cloud-native deployment | TBD |

---

## Appendix A: References

1. Netdev 0x14: HTB Hardware Offload Paper (Yossi Kuperman)
2. Netdev 0x14: Replacing HTB with EDT and BPF (Google)
3. Netdev 0x19: mq-cake Multi-Queue CAKE
4. LANMAN'25: Lockless Rate Limiting Paper
5. LARTC Mailing List: HTB O(1) Class Lookup Patch
6. LibreQoS Documentation and Hardware Guidelines
7. Cloudflare: Conntrack Tales
8. Accel-PPP Official Documentation
9. FreeRADIUS Documentation
10. Maghemite (Oxide Computer) - Rust routing stack
11. Aya - Pure Rust eBPF library

---

*Document created: 2026-05-28*
*Last updated: 2026-05-28*
*Author: PungliOS Team*
