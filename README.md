# PungliOS — Sistem Operasi Pungutan Liar untuk Jaringan ISP/WISP

**"Kalo negara bisa pungli, kenapa router enggak?"**

PungliOS adalah platform manajemen jaringan ISP/WISP berbasis Rust yang terinspirasi dari budaya birokrasi Indonesia. Sama seperti pungutan liar yang efisien, transparan (kagak), dan selalu tepat sasaran (ke kantong sendiri) — PungliOS mengelola bandwidth, routing, dan QoS dengan ketegasan seorang oknum yang minta "uang rokok".

Bedanya? Kalo pungli bikin rakyat susah, PungliOS bikin **ISP untung besar** dengan infrastruktur open-source yang kenceng, stabil, dan zero toleransi terhadap *latency* — tapi toleransi tinggi terhadap sarkasme.

> **Status:** 🟢 Fase 1 (Core Networking) selesai — interface, firewall, QoS, NAT, routing, conntrack, config, CLI/TUI. 🟢 Fase 2 (PPPoE + Auth + Services) selesai — discovery, PPP, RADIUS, user management, DHCP server, DNS forwarder + adblock.
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

### Trait Tambahan Phase 2 (4 Perppu)

| Trait / Module | Method | Mirip Kayak |
|-------|--------|-------------|
| `PppoeBackend` | `send`, `recv`, `bind`, `unbind` | Pungli lewat pos jaga: ngirim amplop, terima lampu hijau |
| `PppoeClient` | `discover`, `disconnect` | Ngurus izin — PADI → PADO → PADR → PADS, kayak ngurus KTP: datang, ngisi formulir, foto, bayar (kalo perlu "uang administrasi") |
| `PppoeServer` | `process_one`, `PADI/PADO/PADR/PADS/PADT` | Pelayanan satu pintu — nunggu setoran, keluarin PADO kalo cocok, kalo gak ya ditolak kayak proposal bansos fiktif |
| `PppNegotiation` | LCP, PAP/CHAP, IPCP | Negosiasi kayak lobby DPR: LCP (salam-salaman), PAP (isi formulir), CHAP (tanda tangan basah), IPCP (minta jatah IP) |
| `RadiusClient` | `authenticate`, `accounting_start/stop/interim` | Mirip sistem pajak: tiap transaksi dicatat, kalo gak bayar ya diblokir |
| `RadiusSessionManager` | `start/stop_accounting`, `update_stats` | Catet pemakaian kayak Ditjen Pajak: masuk berapa, keluar berapa, durasi berapa |
| `UserManager` | `create/get/update/delete user`, `assign_package`, `assign_ip/mac` | Data base user kayak database kependudukan — bedanya ini **beneran** akurat |
| `DhcpServer` | Discover→Offer→Request→Ack, IP pool, lease, reserved IPs | Ngasih IP kayak bagi-bagi sembako: cuma ini gak perlu antri, langsung dapet |

### Manager API Tambahan

- **PppoeClient** — `discover()` → `(session_id, ac_name)`. Mirip pengajuan KUR: ngirim permohonan (PADI), ditawarin (PADO), konfirmasi (PADR), dapet SK (PADS).
- **PppoeServer** — `process_one(iface)` — terima setoran masuk, proses PADI/PADR, kirim PADO/PADS. Kalo penuh, ditolak kayak rumah sakit BPJS.
- **PppNegotiation** — LCP + PAP/CHAP + IPCP. Client dan server mode. `start_lcp()` → `process_frame()` → `start_auth()` → `start_ipcp()`. Kayak ngurus proyek: LCP (MoU), auth (tanda tangan kontraktor), IPCP (cairin anggaran).
- **RadiusClient** — `authenticate(username, password, calling_station_id)` → `RadiusPacket`. `accounting_start/stop/interim(...)` — laporan pertanggungjawaban fiktif.
- **UserManager** — CRUD user + package. `assign_package("budi", "silver")` — kasih paket kayak bagi jabatan.
- **DhcpServer** — `handle_packet()` otomatis route Discover→Offer, Request→Ack. Pool IP: `192.168.1.100` sampai `.200`. Kayak lapak pasar — siapa cepat dia dapet, yang telat ya tunggu expired.

### CLI

```
punglios interface <list|get|create|delete|up|down|mtu|address|vlan|bridge>
punglios firewall <zone|rule> <list|get|create|delete|add-rule|remove-rule|flush>
punglios qos <attach|add-class|remove-class|list>
punglios config <show|apply|commit|rollback|diff>
punglios shell          # TUI — Dashboard, Interfaces, Firewall, QoS, Config, Logs
punglios pppoe          # (TODO: Phase 2 CLI — discovery + session management)
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
- **PPPoE + RADIUS sudah jalan** — Rust-native PPPoE discovery (PADI/PADO/PADR/PADS/PADT), LCP/IPCP negotiation, PAP/CHAP auth, RADIUS client (auth + accounting). **Udah bisa konek, tinggal nyari duit.**
- **DHCP server sudah jalan** — Discover→Offer→Request→Ack full DORA, IP pool management, lease tracking, reserved IPs. Kayak bagi-bagi sembako, cuma ini gak antri.
- **User management sudah jalan** — CRUD user, paket/bandwidth profile, IP/MAC binding. Data base user yang **beneran** akurat — beda sama e-KTP.
- **REST API + Web UI** masih fase berikutnya. Sabar, ini bukan bansos.
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
| PPPoE | **✅ Rust-native** | Built-in | pppd | pppd |
| RADIUS | **✅ Rust-native** | Built-in | freeradius | freeradius |
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

users:
  - username: pelanggan-a               # Rakyat jelata
    password: rahasia123
    enabled: true
    package_name: silver
    ip_address: 10.0.1.100              # IP khusus (biar gampang dilacak kalo telat bayar)
    mac_address: "aa:bb:cc:dd:ee:01"

packages:
  - name: silver                        # Paket silver: 10Mbps (mirip jatah subsidi)
    description: "10Mbps - cukup buat streaming, gak cukup buat download bajakan"
    profiles:
      - name: 10mbps
        upload_rate: 10000
        download_rate: 10000
        priority: 3
  - name: gold                          # Paket gold: prioritas (kayak proyek prioritas nasional)
    description: "50Mbps - buat yang mampu nyogok"
    profiles:
      - name: 50mbps
        upload_rate: 50000
        download_rate: 50000
        priority: 1

dhcp:
  pools:
    - subnet: 10.0.1.0
      mask: 255.255.255.0
      gateway: 10.0.1.1
      start_ip: 10.0.1.100
      end_ip: 10.0.1.200
      dns_servers: [8.8.8.8, 8.8.4.4]
      lease_seconds: 86400
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
