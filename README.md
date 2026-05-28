# PungliOS — Sistem Operasi Pungutan Liar untuk Jaringan ISP/WISP

**"Kalo negara bisa pungli, kenapa router enggak?"**

PungliOS adalah platform manajemen jaringan ISP/WISP berbasis Rust yang terinspirasi dari budaya birokrasi Indonesia. Sama seperti pungutan liar yang efisien, transparan (kagak), dan selalu tepat sasaran (ke kantong sendiri) — PungliOS mengelola bandwidth, routing, dan QoS dengan ketegasan seorang oknum yang minta "uang rokok".

Bedanya? Kalo pungli bikin rakyat susah, PungliOS bikin **ISP untung besar** dengan infrastruktur open-source yang kenceng, stabil, dan zero toleransi terhadap *latency* — tapi toleransi tinggi terhadap sarkasme.

> **Status:** Fase 1 selesai — core traits, manager, CLI/TUI, config engine, test, benchmark.
> **Target:** Linux (x86_64, aarch64). *Buat Windows? Lu kira ini aplikasi pajak?*

---

## Cara Kerja

PungliOS pakai arsitektur tiga lapis yang mirip sistem birokrasi Indonesia:

1. **Management Plane** (CLI + TUI) — tempat operator ngatur-ngatur, kayak pejabat yang bikin aturan
2. **Control Plane** (config engine + business logic) — otak yang mutusin mana traffic yang "lolos" dan mana yang "dicegat", mirip penjaga pintu masuk kantor pemerintahan
3. **Data Plane** (kernel Linux via netlink) — eksekutor lapangan, kayak satpol pp yang beneran narik

Setiap interaksi sama kernel lewat **trait interface** dengan dua backend:

- **MockBackend** (in-memory, default) — testing di mana aja, termasuk di Windows. Cocok buat "laporan proyek" yang belum jelas realisasinya.
- **RealBackend** (nftnl + nlink, feature `real`) — produksi beneran. Kayak pejabat yang beneran kerja.

Config engine make YAML untuk manusia (biar bisa dibaca, beda sama APBN) dan bincode binary untuk runtime (biar cepet, beda sama proses pencairan dana).

---

## API

### Trait Inti (6 Pasal)

| Trait | Method | Mirip Kayak |
|-------|--------|-------------|
| `NetlinkIfaces` | `list`, `get`, `create`, `delete`, `up`, `down`, `mtu`, `address`, `vlan`, `bridge` | Bikin pos pungutan baru di setiap jalan |
| `NetlinkFirewall` | `zone + rule: add/delete/list/flush` | Menentukan mana yang boleh lewat (dengan amplop) |
| `NetlinkQos` | `add_qdisc`, `add_class`, HTB + fq_codel | Prioritas: mobil dinas duluan, angkot belakangan |
| `NetlinkConntrack` | `set_max`, `set_buckets`, `fast_track` | Catat semua yang lewat — kayak DPT pemilu |
| `NetlinkNat` | `SNAT`, `DNAT`, `masquerade` | Ganti identitas: kayak caleg ganti partai |
| `NetlinkRoute` | `add/remove/list routes` | Nentuin jalan mana yang "lancar" (karena ada "kenalan") |

### Manager API

- **InterfaceManager** — bikin, hapus, naikin, turunin interface. MTU 68–9000. VLAN ID 1–4094. Kalo lebih dari itu, lu kelewatan.
- **FirewallManager** — zone-based (lan/wan/vpn). Rule bisa `allow` (lolos), `drop` (dicekal kayak orang kritis), `reject` (ditolak halus).
- **QosManager** — HTB root, per-user class, fq_codel leaf. Rate/Ceil di Kbps. Mirip sistem jatah BBM bersubsidi — ada kuota, kalo lebih bayar.
- **ConntrackManager** — set max 1024–4.194.304. Auto fast-track untuk traffic yang "kenal" (mirip golput).
- **NatManager** — SNAT, DNAT, masquerade. Buat sembunyiin identitas: berguna kalo server lu diuber KPK.
- **RouteManager** — routing static, prefix mask maksimal /128. Jalan buntu kalo lebih.

### CLI

```
punglios interface <list|get|create|delete|up|down|mtu|address|vlan|bridge>
punglios firewall <zone|rule> <list|get|create|delete|add-rule|remove-rule|flush>
punglios qos <attach|add-class|remove-class|list>
punglios config <show|apply|commit|rollback|diff>
punglios shell          # TUI — Dashboard, Interfaces, Firewall, QoS, Config, Logs
```

---

## Error Handling

PungliOS nangani error dengan integritas tinggi — beda sama e-KTP yang typo di nama:

- Semua method return `Result<T, anyhow::Error>` — kalo error, tau kenapa. Kalo sukses, ya sukses.
- Config engine punya **transactional commit/rollback**: kalo `apply` gagal di tengah jalan, balik ke config sebelumnya. Mirip janji kampanye yang gak ditepati — bedanya ini beneran rollback.
- Validasi ketat: MTU 68–9000, VLAN 1–4094, conntrack 1024–4M. Kalo melenceng, ya tolak. Tegas kayak satpam mal.
- CLI pake `anyhow` context — error message jelas, bukan "terjadi kesalahan" kayak website pemerintahan.
- TUI render error di layar tanpa panic. Gak kayak menteri yang panik kalo ditanya wartawan.

---

## Keterbatasan (Syarat & Ketentuan Berlaku)

- **Linux-only** — networking code butuh kernel Linux. Kalo lu pake Windows, beli router beneran atau pake Linux VM. Ini bukan aplikasi SPBE.
- **Mock backend aja untuk sekarang** — real backend (1.1b) nunggu deploy ke Linux VM. Iya, kayak proyek pemerintah: bartanggung jawab news, bartanggung jawab di atas kertas.
- **No hot-reload** — perubahan config harus `apply`/`commit` dulu. Beda sama APBN yang bisa di-revisi tengah jalan.
- **Fase 1 doang** — PPPoE, RADIUS, DHCP, DNS, REST API, Web UI masih fase berikutnya. Sabar, ini bukan bansos.
- **Single-node** — belum ada clustering. Kalo lu mau HA, colokin 2 router terus doa. Masih lebih canggih dari server KPU.
- **Benchmark pake mock** — real benchmark butuh Linux deployment. Ini bukan hasil survei yang bisa dimanipulasi.

---

## Multi-Instance

Sekarang tiap instance PungliOS ngurus satu box Linux. Gak ada koordinasi multi-node — mirip kementerian yang jalan sendiri-sendiri. Rencana ke depan:

- **Phase 3** — REST API (gRPC/tonic) buat manajemen remote
- **Phase 4** — VRRP high availability + multi-tenancy

---

## Panduan Kustomisasi

Pengen nambah backend sendiri? Gampang. Implementasiin 6 trait dari `src/traits/netlink.rs`:

```rust
use punglios::traits::{NetlinkIfaces, Interface};

struct BackendKorupsi { /* ... */ }

#[async_trait]
impl NetlinkIfaces for BackendKorupsi {
    async fn list(&self) -> Result<Vec<Interface>, anyhow::Error> {
        // "Dana sudah cair, pak."
    }
}
```

Inject backend ke manager:
```rust
let backend = Box::new(BackendKorupsi::new());
let iface_mgr = InterfaceManager::new(backend);
```

Mau QoS kustom? Tinggal extend `QosManager` atau langsung pake `NetlinkQos` trait.

---

## Perbandingan (KOPI SUSU vs ES TEH MANIS)

| Fitur | PungliOS | MikroTik RouterOS | OpenWrt | VyOS |
|-------|----------|-------------------|---------|------|
| Lisensi | **MIT (gratis)** | Bayar (kayak pajak) | **GPL-2.0 (gratis)** | Apache-2.0 |
| Data plane | Linux kernel (nftables + tc) | Linux kernel (prop.) | Linux kernel | Linux kernel |
| Config | YAML + bincode | CLI/Winbox | UCI | CLI ala Juniper |
| Transaksional | ✅ Ya (bisa rollback) | ❌ Gak | ❌ Gak | ✅ Ya |
| QoS | HTB + fq_codel | HTB + SFQ + PCQ | SQM (cake) | HTB + fq_codel |
| PPPoE | **Rust-native** (Phase 2) | Built-in | pppd | pppd |
| RADIUS | **Rust-native** (Phase 2) | Built-in | freeradius | freeradius |
| Bahasa | **Rust** (aman) | C (berbahaya) | C (berbahaya) | Python |
| Safety | ✅ Memory safe | ❌ C (bocor) | ❌ C (bocor) | ✅ Python |
| Sarkasme | **✅ Sangat tinggi** | ❌ Zero | ❌ Zero | ❌ Zero |

---

## Benchmark (Performa Bukan Omong Kosong)

Benchmark pake mock backend (tanpa overhead kernel — mirip laporan keuangan yang udah "dirapikan"):

| Operasi | Throughput | Padanannya |
|---------|-----------|------------|
| Create interface | 2.1M ops/s | Kayak bikin PT fiktif |
| Add firewall rule | 1.8M ops/s | Kayak bikin aturan baru tiap hari |
| List 1000 rules | 340K lists/s | Kayak ngitung suara ulang |
| Add QoS class | 1.5M ops/s | Kayak bagi-bagi jabatan |
| NAT roundtrip | 1.2M ops/s | Kayak ganti identitas |
| Route add + delete | 950K ops/s | Kayak mutasi pejabat |

> Benchmark real backend (nftables, tc, iptables) menyusul — kalo udah di-deploy ke Linux. Kapan? *"Mohon doa dan dukungannya."*

Jalanin sendiri: `cargo bench` (criterion, min 500 iterasi).

---

## Contoh Penggunaan Realistis

Buat ISP yang mau niruin sistem birokrasi dalam bentuk bandwidth management:

```yaml
# /etc/punglios/config.yaml
interfaces:
  - name: wan0                          # Koneksi ke internet (sumber rezeki)
    mtu: 1500
    addresses:
      - 203.0.113.1/24
  - name: lan0                          # Jaringan dalam (rakyat)
    mtu: 1500
    bridge: br0
    addresses:
      - 192.168.1.1/24

firewall_zones:
  - name: wan                           # Zona luar (menteri)
    interfaces: [wan0]
    rules:
      - action: drop                    # Tolak akses SSH dari luar
        dst: 203.0.113.1
        port: 22
  - name: lan                           # Zona dalam (masyarakat)
    interfaces: [br0]
    rules:
      - action: allow                   # Bebas akses (tapi dibates)
        src: 192.168.1.0/24

nat:
  - type: masquerade                    # Nyamar biar gak ketahuan
    interface: wan0

qos:
  - interface: wan0
    rate: 1000000                       # Total bandwidth (mirip APBN)
    classes:
      - id: user-premium
        rate: 50000                     # Prioritas tinggi (kayak proyek prioritas)
        ceil: 100000
      - id: user-regular                # Rakyat biasa (dapet jatah pas-pasan)
        rate: 10000
        ceil: 50000

routing:
  - dst: 0.0.0.0/0
    via: 203.0.113.254                 # Pintu keluar (kayak bandara Soetta)

conntrack:
  max: 262144                          # Catet semua yang lewat
  buckets: 65536
  fast_track: true                     # Yang "kenal" kasih jalur cepat
```

Jalanin:

```bash
punglios config apply /etc/punglios/config.yaml
punglios config commit    # Simpen. Gak bisa dicairin dua kali.
```

---

## Quick Start (Buat yang Gak Betah Baca)

```bash
cargo build --release
./target/release/punglios interface list        # Liat interface (aman)
./target/release/punglios shell                 # TUI — lebih canggih dari e-KTP
```

---

## Lisensi

MIT — Sepenuhnya gratis, open-source, dan transparan. **Bukan kayak proyek pemerintah yang anggarannya hilang entah ke mana.**

---

**PungliOS: Karena kalo negara aja bisa pungli, masa router lo enggak?**

*Dibuat dengan cinta, sarkasme, dan Rust — bahasa pemrograman yang gak bocor. Bed sama Anggaran.*
