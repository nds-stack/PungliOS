use criterion::{Criterion, criterion_group, criterion_main};

use punglios::traits::{
    self, ClassConfig, FirewallAction, FirewallRule, FirewallZone, InterfaceConfig, MockBackend,
    QdiscConfig, QdiscKind, Route,
};

fn bench_mock_backend(c: &mut Criterion) {
    let mut group = c.benchmark_group("mock_backend");

    group.bench_function("create_interface", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();
                let config = InterfaceConfig {
                    name: "bench0".into(),
                    mtu: None,
                    addresses: vec![],
                    vlan_id: None,
                    bridge: None,
                };
                NetlinkIfaces::create(&backend, &config).await.unwrap();
            });
    });

    group.bench_function("add_firewall_rule", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();
                NetlinkFirewall::create_zone(
                    &backend,
                    &FirewallZone {
                        name: "test".into(),
                        interfaces: vec![],
                        forward: None,
                        input: None,
                        output: None,
                    },
                )
                .await
                .unwrap();
                NetlinkFirewall::add_rule(
                    &backend,
                    &FirewallRule {
                        handle: 0,
                        zone: "test".into(),
                        chain: "forward".into(),
                        protocol: Some("tcp".into()),
                        src_addr: None,
                        dst_addr: None,
                        src_port: None,
                        dst_port: Some(443),
                        action: FirewallAction::Accept,
                        positions: 0,
                    },
                )
                .await
                .unwrap();
            });
    });

    group.bench_function("list_1000_rules", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();
                NetlinkFirewall::create_zone(
                    &backend,
                    &FirewallZone {
                        name: "test".into(),
                        interfaces: vec![],
                        forward: None,
                        input: None,
                        output: None,
                    },
                )
                .await
                .unwrap();
                for i in 0..1000 {
                    NetlinkFirewall::add_rule(
                        &backend,
                        &FirewallRule {
                            handle: 0,
                            zone: "test".into(),
                            chain: "forward".into(),
                            protocol: None,
                            src_addr: None,
                            dst_addr: None,
                            src_port: None,
                            dst_port: Some((i % 65535) as u16),
                            action: FirewallAction::Accept,
                            positions: 0,
                        },
                    )
                    .await
                    .unwrap();
                }
                NetlinkFirewall::list_rules(&backend, "test").await.unwrap();
            });
    });

    group.bench_function("add_qos_class", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();
                NetlinkQos::add_qdisc(
                    &backend,
                    &QdiscConfig {
                        kind: QdiscKind::Htb,
                        iface: "eth0".into(),
                        handle: 0x10,
                        parent: 0,
                        rate: Some(1_000_000_000),
                        ceil: Some(1_000_000_000),
                    },
                )
                .await
                .unwrap();
                NetlinkQos::add_class(
                    &backend,
                    &ClassConfig {
                        iface: "eth0".into(),
                        classid: 0x10_01,
                        parent: 0x10,
                        rate: 100_000_000,
                        ceil: 100_000_000,
                        burst: None,
                        cburst: None,
                        priority: 3,
                    },
                )
                .await
                .unwrap();
            });
    });

    group.bench_function("nat_roundtrip", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();

                let handle = NetlinkNat::add_rule(
                    &backend,
                    &traits::NatRule {
                        handle: 0,
                        iface: "wan".into(),
                        kind: traits::NatKind::Masquerade,
                        src_addr: None,
                        dst_addr: None,
                        to_addr: None,
                        to_port: None,
                    },
                )
                .await
                .unwrap();

                NetlinkNat::list_rules(&backend).await.unwrap();
                NetlinkNat::delete_rule(&backend, handle).await.unwrap();
            });
    });

    group.bench_function("route_add_delete", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockBackend::new();
                let route = Route {
                    destination: "10.0.0.0".parse().unwrap(),
                    prefix: 24,
                    nexthop: Some("192.168.1.1".parse().unwrap()),
                    iface: Some("eth0".into()),
                    metric: Some(100),
                };
                NetlinkRoute::add_route(&backend, &route).await.unwrap();
                NetlinkRoute::list_routes(&backend).await.unwrap();
                NetlinkRoute::delete_route(&backend, "10.0.0.0".parse().unwrap(), 24)
                    .await
                    .unwrap();
            });
    });

    group.finish();
}

use traits::{NetlinkFirewall, NetlinkIfaces, NetlinkNat, NetlinkQos, NetlinkRoute};

criterion_group!(benches, bench_mock_backend);
criterion_main!(benches);
