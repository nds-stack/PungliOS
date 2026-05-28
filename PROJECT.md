# PROJECT.md — Visi, Arsitektur, Filosofi PungliOS

## Visi

Menjadi platform networking open-source berperforma tinggi yang bisa menggantikan solusi proprietary seperti MikroTik RouterOS untuk kebutuhan ISP/WISP di Indonesia — dengan performa superior dan biaya hardware minimal.

## Filosofi

### 1. Rust-First, Kernel-Friendly

Kita tidak membuat kernel sendiri. PungliOS berdiri di atas Linux kernel yang sudah terbukti. Yang kita bangun adalah **control plane** — manajemen konfigurasi, generate ruleset, auto-tuning — semuanya dalam Rust.

```
"Don't build a kernel. Build the brain that controls it."
```

### 2. Trait-Based Abstraction

Setiap interaksi dengan kernel (netlink, nftables, tc) melewati trait. Ini memungkinkan:

- **Testing everywhere** — mock backend di Windows/CI tanpa kernel Linux
- **Swap implementations** — ganti backend tanpa ubah kode aplikasi
- **Clear contracts** — interface yang jelas antara komponen

### 3. Config as Source of Truth

Konfigurasi adalah single source of truth. Semua state deducible dari config file. Ini memungkinkan:

- **Transactional changes** — commit/rollback atomic
- **Version control** — config bisa di-git, di-diff, di-review
- **Reproducibility** — deploy ulang dari config yang sama = hasil yang sama

### 4. Auto-Tuning over Manual Configuration

MikroTik memaksa user untuk mengerti connection tracking, fast-track, rule ordering. PungliOS harus pintar sendiri:

- **Conntrack:** Auto-adjust max_entries dan buckets berdasarkan available RAM
- **Fast-track:** Auto-enable untuk high-volume traffic
- **QoS:** Auto-classify traffic patterns, rekomendasi rule optimization

### 5. Observability Built-In

Setiap komponen harus emit metrics. Tidak boleh ada "black box":

- **Per-rule counters:** CPU time, packet count, byte count
- **Per-class bandwidth:** Real-time throughput monitoring
- **Health checks:** Service status, error rates, latency

### 6. Graceful Degradation

Failure di satu komponen tidak boleh crash seluruh system:

- PPPoE server failure → client existing tetap jalan
- Config parse error → rollback ke config terakhir yang valid
- nftables rule error → skip rule yang bermasalah, lanjut apply sisanya

## Arsitektur

### Three-Plane Architecture

```
┌──────────────────────────────────────┐
│         Management Plane             │
│  CLI (clap + ratatui)                │
│  REST API + Web UI (Phase 3)        │
│  ← User-facing interfaces            │
├──────────────────────────────────────┤
│         Control Plane                │
│  Config Engine (YAML → bincode)     │
│  PPPoE Server + RADIUS (Phase 2)    │
│  QoS Policy Engine                  │
│  ← Business logic, orchestration     │
├──────────────────────────────────────┤
│         Data Plane                   │
│  Trait Layer (NetlinkIfaces, etc.)   │
│  Mock Backend │ Real Backend         │
│  (nftnl + nlink + netlink)          │
│  ← Kernel interaction                │
├──────────────────────────────────────┤
│         Linux Kernel                 │
│  Netfilter │ tc │ eBPF │ conntrack  │
└──────────────────────────────────────┘
```

### Component Dependency

```
Core Traits (1.1a)
     │
     ├── Mock Backend ──▶ Tests everywhere
     └── Real Backend ──▶ Production (Linux)
              │
              ├── Interface Manager (1.2)
              │     ├── nftables (1.3) ── NAT (1.8)
              │     ├── tc QoS (1.4)
              │     ├── Conntrack (1.5)
              │     └── Static Routes (1.9)
              │
              └── Config Engine (1.6)
                    └── CLI (1.7)
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Data plane | Linux kernel (nftables + tc) | No kernel bypass needed for <10 Gbps |
| PPPoE | Rust-native (no Accel-PPP) | Full control, memory safety, no C |
| Config format | YAML (human) + bincode (runtime) | Readable + type-safe binary |
| IPC | tonic/gRPC + protobuf | Industry standard, streaming |
| Mock backend | In-memory (HashMap + Vec) | Fast tests, no kernel required |
| Async runtime | Tokio | Industry standard Rust async |

## Non-Goals (Out of Scope)

- **GUI desktop app** — CLI + Web UI only
- **Windows/Mac support** — Linux only (x86_64, aarch64)
- **Custom kernel module** — gunakan yang sudah ada di mainline
- **100+ Gbps data plane** — itu butuh DPDK/VPP, out of scope untuk sekarang
- **Mobile app** — tidak ada rencana

## Inspirasi

| Project | What We Learn |
|---------|---------------|
| **OpenWrt** | UCI config system, zone-based firewall, SQM QoS |
| **VyOS** | Transactional config, commit/rollback, Junos-like CLI |
| **MikroTik RouterOS** | Feature set, integrated management, CLI usability |
| **LibreQoS** | ISP-scale per-subscriber QoS, Rust + cake |
| **Maghemite** | Rust-native BGP/BFD, routing stack architecture |
| **Envoy** | xDS dynamic config, hot reload, observability |

---

*Dibaca oleh developer sebelum kontribusi. Update jika ada perubahan visi atau arsitektur.*
