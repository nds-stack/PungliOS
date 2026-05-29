use criterion::{Criterion, criterion_group, criterion_main};
use punglios::routing::{BgpPeer, DynamicRouting, MockDynamicRouting, RoutingProtocol};
use std::collections::HashMap;

/// Benchmark: MockDynamicRouting vs raw HashMap for BGP peer operations.
fn bench_bgp_peers(c: &mut Criterion) {
    let mut group = c.benchmark_group("bgp_peers");

    // Competitor 1: raw HashMap operations
    group.bench_function("hashmap_baseline", |b| {
        b.iter(|| {
            let mut map: HashMap<String, BgpPeer> = HashMap::new();
            for i in 0..100 {
                let peer = BgpPeer {
                    neighbor_ip: format!("10.0.0.{}", i),
                    remote_asn: 64512,
                    local_asn: 64513,
                    multihop: false,
                    password: None,
                    enabled: true,
                    description: None,
                };
                map.insert(peer.neighbor_ip.clone(), peer);
            }
            for i in 0..100 {
                let _ = map.get(&format!("10.0.0.{}", i));
            }
        })
    });

    // PungliOS MockDynamicRouting
    group.bench_function("mock_routing_add", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let backend = MockDynamicRouting::new();
            for i in 0..100 {
                let peer = BgpPeer {
                    neighbor_ip: format!("10.0.0.{}", i),
                    remote_asn: 64512,
                    local_asn: 64513,
                    multihop: false,
                    password: None,
                    enabled: true,
                    description: None,
                };
                backend.add_bgp_peer(&peer).await.unwrap();
            }
        });
    });

    // Competitor 2: Vec-based lookup (alternative naive approach)
    group.bench_function("vec_baseline", |b| {
        b.iter(|| {
            let mut peers: Vec<BgpPeer> = Vec::new();
            for i in 0..100 {
                let peer = BgpPeer {
                    neighbor_ip: format!("10.0.0.{}", i),
                    remote_asn: 64512,
                    local_asn: 64513,
                    multihop: false,
                    password: None,
                    enabled: true,
                    description: None,
                };
                if !peers.iter().any(|p| p.neighbor_ip == peer.neighbor_ip) {
                    peers.push(peer);
                }
            }
            for _ in 0..100 {
                let _ = peers.iter().find(|p| p.neighbor_ip == "10.0.0.50");
            }
        })
    });

    group.finish();
}

fn bench_ospf_areas(c: &mut Criterion) {
    let mut group = c.benchmark_group("ospf_areas");

    group.bench_function("hashmap_baseline", |b| {
        b.iter(|| {
            let mut map: HashMap<String, String> = HashMap::new();
            for i in 0..100 {
                map.insert(format!("area-{i}"), format!("desc-{i}"));
            }
            for i in 0..100 {
                let _ = map.get(&format!("area-{i}"));
            }
        })
    });

    group.bench_function("mock_routing_areas", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let backend = MockDynamicRouting::new();
            for i in 0..100 {
                let area = punglios::routing::OspfArea {
                    area_id: format!("0.0.0.{i}"),
                    interfaces: vec!["eth0".into()],
                    networks: vec!["10.0.0.0/24".into()],
                    enabled: true,
                };
                backend.add_ospf_area(&area).await.unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_bgp_peers, bench_ospf_areas);
criterion_main!(benches);
