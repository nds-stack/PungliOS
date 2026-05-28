use punglios::{
    firewall::nat::NatManager,
    firewall::FirewallManager,
    net::iface::InterfaceManager,
    net::route::RouteManager,
    qos::QosManager,
    traits::{
        FirewallAction, FirewallRule, FirewallZone, InterfaceConfig, MockBackend,
        Route,
    },
};

fn setup_backend() -> MockBackend {
    MockBackend::new()
}

#[tokio::test]
async fn test_full_network_setup() {
    let backend = setup_backend();
    let iface_mgr = InterfaceManager::new(backend.clone());
    let fw_mgr = FirewallManager::new(backend.clone());
    let qos_mgr = QosManager::new(backend.clone());
    let nat_mgr = NatManager::new(backend.clone());
    let route_mgr = RouteManager::new(backend.clone());

    // 1. Create interfaces
    let wan = iface_mgr
        .create(&InterfaceConfig {
            name: "wan".into(),
            mtu: Some(1500),
            addresses: vec!["203.0.113.1".parse().unwrap()],
            vlan_id: None,
            bridge: None,
        })
        .await
        .unwrap();
    assert_eq!(wan.name, "wan");

    let lan = iface_mgr
        .create_vlan("eth0", 100)
        .await
        .unwrap();
    assert_eq!(lan.name, "eth0.100");

    // 2. Create firewall zones
    fw_mgr
        .create_zone(&FirewallZone {
            name: "wan".into(),
            interfaces: vec!["wan".into()],
            forward: Some(FirewallAction::Drop),
            input: Some(FirewallAction::Drop),
            output: Some(FirewallAction::Accept),
        })
        .await
        .unwrap();

    fw_mgr
        .create_zone(&FirewallZone {
            name: "lan".into(),
            interfaces: vec!["eth0.100".into()],
            forward: Some(FirewallAction::Accept),
            input: Some(FirewallAction::Accept),
            output: Some(FirewallAction::Accept),
        })
        .await
        .unwrap();

    // 3. Add firewall rules
    let handle = fw_mgr
        .add_rule(&FirewallRule {
            handle: 0,
            zone: "wan".into(),
            chain: "forward".into(),
            protocol: Some("tcp".into()),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: Some(80),
            action: FirewallAction::Accept,
            positions: 0,
        })
        .await
        .unwrap();
    assert!(handle > 0);

    // 4. Setup QoS
    qos_mgr.create_htb_root("eth0.100", 1_000_000_000).await.unwrap();
    qos_mgr
        .create_user_class("eth0.100", 0x10_01, 100_000_000, 100_000_000)
        .await
        .unwrap();

    // 5. Add NAT
    let masq = nat_mgr.add_masquerade("wan").await.unwrap();
    assert!(masq > 0);

    // 6. Add routes
    let default_route = route_mgr.add_default_via("203.0.113.254".parse().unwrap());
    route_mgr.add_route(&default_route).await.unwrap();
    route_mgr
        .add_route(&Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 8,
            nexthop: Some("10.0.0.1".parse().unwrap()),
            iface: Some("eth0.100".into()),
            metric: Some(100),
        })
        .await
        .unwrap();

    // 7. Assertions
    assert_eq!(iface_mgr.list().await.unwrap().len(), 2);
    assert_eq!(fw_mgr.list_rules("wan").await.unwrap().len(), 1);
    assert_eq!(nat_mgr.list_rules().await.unwrap().len(), 1);
    assert_eq!(route_mgr.list_routes().await.unwrap().len(), 2);
}

#[tokio::test]
async fn test_interface_lifecycle() {
    let backend = setup_backend();
    let mgr = InterfaceManager::new(backend);

    let config = InterfaceConfig {
        name: "test0".into(),
        mtu: None,
        addresses: vec![],
        vlan_id: None,
        bridge: None,
    };

    let iface = mgr.create(&config).await.unwrap();
    assert_eq!(iface.name, "test0");

    mgr.set_down("test0").await.unwrap();
    let iface = mgr.get("test0").await.unwrap();
    assert!(!iface.up);

    mgr.set_up("test0").await.unwrap();
    let iface = mgr.get("test0").await.unwrap();
    assert!(iface.up);

    mgr.set_mtu("test0", 9000).await.unwrap();
    let iface = mgr.get("test0").await.unwrap();
    assert_eq!(iface.mtu, 9000);

    let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    mgr.add_address("test0", addr).await.unwrap();
    let iface = mgr.get("test0").await.unwrap();
    assert!(iface.addresses.contains(&addr));

    mgr.delete("test0").await.unwrap();
    assert!(mgr.get("test0").await.is_err());
}

#[tokio::test]
async fn test_vlan_and_bridge() {
    let backend = setup_backend();
    let mgr = InterfaceManager::new(backend);

    mgr.create_vlan("eth0", 10).await.unwrap();
    mgr.create_vlan("eth0", 20).await.unwrap();
    assert_eq!(mgr.list().await.unwrap().len(), 2);

    mgr.add_to_bridge("eth0.10", "br-lan").await.unwrap();
    let iface = mgr.get("eth0.10").await.unwrap();
    assert_eq!(iface.name, "eth0.10");
}

#[tokio::test]
async fn test_firewall_multiple_zones() {
    let backend = setup_backend();
    let mgr = FirewallManager::new(backend);

    for zone_name in &["lan", "wan", "vpn", "dmz", "guest"] {
        mgr.create_zone(&FirewallZone {
            name: zone_name.to_string(),
            interfaces: vec![],
            forward: Some(FirewallAction::Drop),
            input: Some(FirewallAction::Drop),
            output: Some(FirewallAction::Accept),
        })
        .await
        .unwrap();
    }

    for zone in &["lan", "wan", "vpn"] {
        let rules = mgr.list_rules(zone).await.unwrap();
        assert!(rules.is_empty());
    }
}

#[tokio::test]
async fn test_qos_hierarchy() {
    let backend = setup_backend();
    let mgr = QosManager::new(backend);

    mgr.create_htb_root("eth0", 1_000_000_000).await.unwrap();

    mgr.create_user_class("eth0", 0x10_01, 500_000_000, 500_000_000)
        .await
        .unwrap();
    mgr.create_user_class("eth0", 0x10_02, 300_000_000, 300_000_000)
        .await
        .unwrap();
    mgr.create_user_class("eth0", 0x10_03, 200_000_000, 200_000_000)
        .await
        .unwrap();

    mgr.attach_fq_codel("eth0", 0x10_01).await.unwrap();
    mgr.attach_fq_codel("eth0", 0x10_02).await.unwrap();
    mgr.attach_fq_codel("eth0", 0x10_03).await.unwrap();
}

#[tokio::test]
async fn test_nat_all_types() {
    let backend = setup_backend();
    let mgr = NatManager::new(backend);

    let snat = mgr.add_snat("wan", None, None).await.unwrap();
    let dnat = mgr
        .add_dnat(
            "wan",
            Some("203.0.113.10".parse().unwrap()),
            Some("192.168.1.100".parse().unwrap()),
            Some(80),
        )
        .await
        .unwrap();
    let masq = mgr.add_masquerade("lan").await.unwrap();

    let rules = mgr.list_rules().await.unwrap();
    assert_eq!(rules.len(), 3);

    mgr.delete_rule(snat).await.unwrap();
    let rules = mgr.list_rules().await.unwrap();
    assert_eq!(rules.len(), 2);

    mgr.delete_rule(dnat).await.unwrap();
    mgr.delete_rule(masq).await.unwrap();
    assert!(mgr.list_rules().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_routing_table() {
    let backend = setup_backend();
    let mgr = RouteManager::new(backend);

    let routes = vec![
        Route {
            destination: "0.0.0.0".parse().unwrap(),
            prefix: 0,
            nexthop: Some("192.168.1.1".parse().unwrap()),
            iface: Some("wan".into()),
            metric: Some(100),
        },
        Route {
            destination: "10.0.0.0".parse().unwrap(),
            prefix: 8,
            nexthop: None,
            iface: Some("eth0".into()),
            metric: None,
        },
        Route {
            destination: "172.16.0.0".parse().unwrap(),
            prefix: 16,
            nexthop: Some("10.0.0.1".parse().unwrap()),
            iface: None,
            metric: Some(10),
        },
    ];

    for route in &routes {
        mgr.add_route(route).await.unwrap();
    }

    let listed = mgr.list_routes().await.unwrap();
    assert_eq!(listed.len(), 3);

    mgr.delete_route("10.0.0.0".parse().unwrap(), 8)
        .await
        .unwrap();
    assert_eq!(mgr.list_routes().await.unwrap().len(), 2);
}
