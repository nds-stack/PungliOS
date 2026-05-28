use punglios::pppoe::auth::{
    self, ACCESS_ACCEPT, ATTR_WISPR_BANDWIDTH_MAX_DOWN, ATTR_WISPR_BANDWIDTH_MAX_UP,
    MockRadiusBackend, RadiusAttribute, RadiusClient, RadiusPacket, UserRecord,
};
use punglios::pppoe::discovery::{MockPppoeBackend, PppoeClient, PppoeServer};
use punglios::pppoe::session::{LCP_CONFIGURE_ACK, PPP_LCP, PppNegotiation};
use punglios::pppoe::types::{
    self, AuthProtocol, PppoeClientConfig, PppoeServerConfig, TAG_AC_NAME,
};
use punglios::user::{BandwidthProfile, MockUserBackend, User, UserManager, UserPackage};
use std::net::Ipv4Addr;

const CLIENT_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn setup_user_manager() -> UserManager<MockUserBackend> {
    UserManager::new(MockUserBackend::new())
}

fn setup_radius_backend() -> MockRadiusBackend {
    let backend = MockRadiusBackend::new("testing123", "nas01");
    backend.add_user(UserRecord::new("user1", "pass1", true));
    backend.add_user(UserRecord::new("user2", "pass2", true));
    backend.add_user(UserRecord::new("banned", "badpass", false));
    backend
}

fn setup_pppoe_server(backend: MockPppoeBackend) -> PppoeServer<MockPppoeBackend> {
    let cfg = PppoeServerConfig {
        interfaces: vec!["eth0".into()],
        ac_name: "punglios-ac-01".into(),
        service_name: Some("my-isp".into()),
        max_sessions: 1024,
    };
    PppoeServer::new(backend, cfg, SERVER_MAC)
}

// ─── PPPoE Discovery + RADIUS + User Integration ─────

#[tokio::test]
async fn test_pppoe_discovery_with_radius_auth() {
    let pppoe_backend = MockPppoeBackend::new();
    let mut server = setup_pppoe_server(pppoe_backend.clone());
    server.bind().await.unwrap();

    let client_cfg = PppoeClientConfig {
        interface: "eth0".into(),
        service_name: Some("my-isp".into()),
        username: "user1".into(),
        password: "pass1".into(),
        auth_protocol: AuthProtocol::Pap,
        host_uniq: Some(vec![0x01, 0x02, 0x03]),
    };
    let mut client = PppoeClient::new(pppoe_backend.clone(), client_cfg, CLIENT_MAC);

    let radius = setup_radius_backend();

    // Client discovers server
    let client_handle = tokio::spawn(async move { client.discover().await });

    // Server processes PADI → PADO
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let pado = server.process_one("eth0").await.unwrap().unwrap();
    assert_eq!(pado.packet.code, types::PADO);
    assert_eq!(
        pado.packet.find_tag_str(TAG_AC_NAME).unwrap(),
        "punglios-ac-01"
    );

    // Server processes PADR → PADS
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let pads = server.process_one("eth0").await.unwrap().unwrap();
    assert_eq!(pads.packet.code, types::PADS);
    let session_id = pads.packet.session_id;
    assert_ne!(session_id, 0);

    let (_sid, _ac_name) = client_handle.await.unwrap().unwrap();

    // RADIUS authenticates the user
    let mut radius_client = RadiusClient::new(radius, Ipv4Addr::new(10, 0, 0, 1), "nas01");
    let auth_result = radius_client
        .authenticate("user1", "pass1", "aa:bb:cc:dd:ee:ff")
        .unwrap();
    assert_eq!(auth_result.code, ACCESS_ACCEPT);
}

#[tokio::test]
async fn test_user_radius_pppoe_full_flow() {
    // Setup user
    let user_mgr = setup_user_manager();
    let user = User {
        username: "user1".into(),
        password: "pass1".into(),
        enabled: true,
        package_name: Some("silver".into()),
        ip_address: Some(Ipv4Addr::new(10, 0, 1, 100)),
        mac_address: None,
        notes: None,
    };
    user_mgr.create_user(user).await.unwrap();

    // Create package
    let pkg = UserPackage {
        name: "silver".into(),
        description: "Silver 10Mbps".into(),
        profiles: vec![BandwidthProfile {
            name: "10mbps".into(),
            upload_rate: 10000,
            download_rate: 10000,
            upload_burst: None,
            download_burst: None,
            priority: 3,
        }],
        session_timeout: Some(86400),
    };
    user_mgr.create_package(pkg).await.unwrap();

    // RADIUS auth
    let radius = setup_radius_backend();
    let mut radius_client = RadiusClient::new(radius, Ipv4Addr::new(10, 0, 0, 1), "nas01");
    let auth_result = radius_client
        .authenticate("user1", "pass1", "aa:bb:cc:dd:ee:ff")
        .unwrap();
    assert_eq!(auth_result.code, ACCESS_ACCEPT);

    // Verify user bandwidth profile
    let profiles = user_mgr.get_user_bandwidth("user1").await.unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].upload_rate, 10000);
    assert_eq!(profiles[0].download_rate, 10000);
}

// ─── User + RADIUS Integration ───────────────────────

#[tokio::test]
async fn test_user_create_and_radius_auth() {
    let user_backend = MockUserBackend::new();

    // Create user via UserManager
    let user_mgr = UserManager::new(user_backend.clone());
    let user = User {
        username: "testuser".into(),
        password: "testpass".into(),
        enabled: true,
        package_name: None,
        ip_address: Some(Ipv4Addr::new(10, 0, 1, 50)),
        mac_address: None,
        notes: None,
    };
    user_mgr.create_user(user).await.unwrap();

    // Create RADIUS backend with same user
    let radius_backend = MockRadiusBackend::new("secret", "nas01");
    radius_backend.add_user(UserRecord::new("testuser", "testpass", true));

    // Authenticate via RADIUS
    let mut radius_client = RadiusClient::new(radius_backend, Ipv4Addr::new(10, 0, 0, 1), "nas01");
    let response = radius_client
        .authenticate("testuser", "testpass", "00:11:22:33:44:55")
        .unwrap();
    assert_eq!(response.code, ACCESS_ACCEPT);

    // Verify user exists in UserManager
    let stored_user = user_mgr.get_user("testuser").await.unwrap();
    assert!(stored_user.enabled);
    assert_eq!(stored_user.ip_address.unwrap(), Ipv4Addr::new(10, 0, 1, 50));
}

#[tokio::test]
async fn test_package_assign_bandwidth_flow() {
    let user_mgr = setup_user_manager();
    let user = User {
        username: "bob".into(),
        password: "bobpass".into(),
        enabled: true,
        package_name: None,
        ip_address: None,
        mac_address: Some("de:ad:be:ef:00:01".into()),
        notes: None,
    };
    user_mgr.create_user(user).await.unwrap();

    // Create packages
    let bronze = UserPackage {
        name: "bronze".into(),
        description: "5Mbps".into(),
        profiles: vec![BandwidthProfile {
            name: "5mbps".into(),
            upload_rate: 5000,
            download_rate: 5000,
            upload_burst: None,
            download_burst: None,
            priority: 5,
        }],
        session_timeout: None,
    };
    user_mgr.create_package(bronze).await.unwrap();

    // Assign bronze package
    user_mgr.assign_package("bob", "bronze").await.unwrap();

    // Verify bandwidth
    let profiles = user_mgr.get_user_bandwidth("bob").await.unwrap();
    assert_eq!(profiles[0].upload_rate, 5000);
    assert_eq!(profiles[0].download_rate, 5000);
    assert_eq!(profiles[0].priority, 5);
}

// ─── Bandwidth Parsing Integration ───────────────────

#[test]
fn test_radius_bandwidth_to_user_profile() {
    let mut pkt = RadiusPacket::new(ACCESS_ACCEPT, 1);
    pkt.attributes
        .push(RadiusAttribute::new_u32(ATTR_WISPR_BANDWIDTH_MAX_UP, 25000));
    pkt.attributes.push(RadiusAttribute::new_u32(
        ATTR_WISPR_BANDWIDTH_MAX_DOWN,
        50000,
    ));

    let profiles = auth::parse_bandwidth_from_response(&pkt);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].upload_rate, 25000);
    assert_eq!(profiles[0].download_rate, 50000);
}

// ─── Multi-session PPPoE Integration ──────────────────

#[tokio::test]
async fn test_multiple_clients_connect_sequentially() {
    let backend = MockPppoeBackend::new();
    let mut server = setup_pppoe_server(backend.clone());
    server.bind().await.unwrap();

    for client_num in 0..3 {
        let cfg = PppoeClientConfig {
            interface: "eth0".into(),
            service_name: Some("my-isp".into()),
            username: format!("user{client_num}"),
            password: format!("pass{client_num}"),
            auth_protocol: AuthProtocol::Pap,
            host_uniq: Some(vec![client_num; 3]),
        };
        let mac = [0xaa, 0xbb, 0xcc, client_num, 0xee, 0xff];
        let mut client = PppoeClient::new(backend.clone(), cfg, mac);

        let handle = tokio::spawn(async move { client.discover().await });

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        server.process_one("eth0").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        server.process_one("eth0").await.unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_ok(), "client {client_num} should connect");
    }

    assert_eq!(server.session_count(), 3);
}

#[tokio::test]
async fn test_pppoe_disconnect_cleans_session() {
    let backend = MockPppoeBackend::new();
    let mut server = setup_pppoe_server(backend.clone());
    server.bind().await.unwrap();

    let cfg = PppoeClientConfig {
        interface: "eth0".into(),
        service_name: None,
        username: "user1".into(),
        password: "pass1".into(),
        auth_protocol: AuthProtocol::Pap,
        host_uniq: None,
    };
    let mut client = PppoeClient::new(backend.clone(), cfg, CLIENT_MAC);

    let handle = tokio::spawn(async move {
        client.discover().await.unwrap();
        client.disconnect().await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    server.process_one("eth0").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    server.process_one("eth0").await.unwrap();

    // Wait for client to connect + disconnect
    handle.await.unwrap();

    // Process PADT
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    server.process_one("eth0").await.unwrap();
    assert_eq!(server.session_count(), 0);
}

// ─── User Auth + LCP Negotiation Integration ──────────

#[tokio::test]
async fn test_lcp_followed_by_pap_after_pppoe() {
    let backend = MockPppoeBackend::new();
    let mut server = setup_pppoe_server(backend.clone());
    server.bind().await.unwrap();

    let cfg = PppoeClientConfig {
        interface: "eth0".into(),
        service_name: None,
        username: "user1".into(),
        password: "pass1".into(),
        auth_protocol: AuthProtocol::Pap,
        host_uniq: None,
    };
    let mut client = PppoeClient::new(backend.clone(), cfg, CLIENT_MAC);
    let handle = tokio::spawn(async move { client.discover().await });
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    server.process_one("eth0").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    server.process_one("eth0").await.unwrap();
    handle.await.unwrap().unwrap();

    let mut neg = PppNegotiation::new_client(backend, "user1", "pass1", AuthProtocol::Pap);
    let lcp_req = neg.start_lcp();
    assert_eq!(lcp_req.protocol, PPP_LCP);

    let mut server_neg =
        PppNegotiation::new_server(MockPppoeBackend::new(), Ipv4Addr::new(10, 0, 0, 1), vec![]);
    let lcp_ack = server_neg.process_frame(&lcp_req).unwrap().unwrap();
    assert_eq!(lcp_ack.code, LCP_CONFIGURE_ACK);
    neg.process_frame(&lcp_ack).unwrap();
    assert!(neg.lcp_state().is_open());
}
