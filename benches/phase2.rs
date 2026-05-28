use criterion::{Criterion, criterion_group, criterion_main};

use punglios::dhcp::{DhcpServer, types::*};
use punglios::pppoe::auth::{
    ATTR_WISPR_BANDWIDTH_MAX_DOWN, ATTR_WISPR_BANDWIDTH_MAX_UP, MockRadiusBackend, RadiusAttribute,
    RadiusClient, UserRecord,
};
use punglios::pppoe::discovery::{MockPppoeBackend, PppoeClient, PppoeServer};
use punglios::pppoe::session::PppNegotiation;
use punglios::pppoe::types::{AuthProtocol, PppoeClientConfig, PppoeServerConfig};
use punglios::user::{MockUserBackend, User, UserBackend};
use std::net::Ipv4Addr;

const CLIENT_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn bench_phase2(c: &mut Criterion) {
    let mut group = c.benchmark_group("phase2");

    group.bench_function("pppoe_discovery_flow", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockPppoeBackend::new();
                let mut server = PppoeServer::new(
                    backend.clone(),
                    PppoeServerConfig {
                        interfaces: vec!["eth0".into()],
                        ac_name: "ac1".into(),
                        service_name: Some("isp".into()),
                        max_sessions: 1024,
                    },
                    SERVER_MAC,
                );
                server.bind().await.unwrap();

                let mut client = PppoeClient::new(
                    backend.clone(),
                    PppoeClientConfig {
                        interface: "eth0".into(),
                        service_name: Some("isp".into()),
                        username: "u".into(),
                        password: "p".into(),
                        auth_protocol: AuthProtocol::Pap,
                        host_uniq: None,
                    },
                    CLIENT_MAC,
                );

                let h = tokio::spawn(async move { client.discover().await });
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let _ = server.process_one("eth0").await;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let _ = server.process_one("eth0").await;
                let _ = h.await;
            });
    });

    group.bench_function("radius_authenticate", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockRadiusBackend::new("secret", "nas01");
                backend.add_user(UserRecord::new("user1000", "pass1000", true));

                let mut client = RadiusClient::new(backend, Ipv4Addr::new(10, 0, 0, 1), "nas01");
                let _ = client
                    .authenticate("user1000", "pass1000", "aa:bb:cc:dd:ee:ff")
                    .unwrap();
            });
    });

    group.bench_function("dhcp_dora_flow", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let pool = IpPool::new(
                    Ipv4Addr::new(10, 0, 0, 0),
                    Ipv4Addr::new(255, 255, 255, 0),
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 100),
                    Ipv4Addr::new(10, 0, 0, 200),
                );
                let mut server = DhcpServer::new(pool, Ipv4Addr::new(10, 0, 0, 1));

                let mut discover = DhcpPacket::new(OP_BOOTREQUEST);
                discover.xid = 0x1000;
                discover.chaddr[..6].copy_from_slice(&CLIENT_MAC);
                discover
                    .options
                    .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_DISCOVER));

                let offer = server.handle_packet(&discover).unwrap();

                let mut request = DhcpPacket::new(OP_BOOTREQUEST);
                request.xid = 0x1001;
                request.chaddr[..6].copy_from_slice(&CLIENT_MAC);
                request
                    .options
                    .push(DhcpOption::new_byte(OPT_DHCP_MESSAGE_TYPE, DHCP_REQUEST));
                request.options.push(DhcpOption::new_ip(50, offer.yiaddr));
                request.options.push(DhcpOption::new_ip(
                    OPT_SERVER_IDENTIFIER,
                    Ipv4Addr::new(10, 0, 0, 1),
                ));

                let _ = server.handle_packet(&request);
            });
    });

    group.bench_function("user_crud", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockUserBackend::new();

                for i in 0..100 {
                    let user = User {
                        username: format!("user{i}"),
                        password: format!("pass{i}"),
                        enabled: true,
                        package_name: None,
                        ip_address: Some(Ipv4Addr::new(10, 0, 0, i)),
                        mac_address: None,
                        notes: None,
                    };
                    backend.create_user(user).await.unwrap();
                }

                let _ = backend.user_count().await.unwrap();
            });
    });

    group.bench_function("lcp_negotiation", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let backend = MockPppoeBackend::new();
                let mut server =
                    PppNegotiation::new_server(backend.clone(), Ipv4Addr::new(10, 0, 0, 1), vec![]);
                let mut client = PppNegotiation::new_client(
                    backend.clone(),
                    "user1",
                    "pass1",
                    AuthProtocol::Pap,
                );

                let req = client.start_lcp();
                let ack = server.process_frame(&req).unwrap().unwrap();
                let _ = client.process_frame(&ack);
            });
    });

    group.bench_function("bandwidth_parsing", |b| {
        b.iter(|| {
            let mut pkt =
                punglios::pppoe::auth::RadiusPacket::new(punglios::pppoe::auth::ACCESS_ACCEPT, 1);
            pkt.attributes
                .push(RadiusAttribute::new_u32(ATTR_WISPR_BANDWIDTH_MAX_UP, 50000));
            pkt.attributes.push(RadiusAttribute::new_u32(
                ATTR_WISPR_BANDWIDTH_MAX_DOWN,
                100000,
            ));
            let val = "rate-limit:50M/100M 5M/10M 3";
            pkt.attributes.push(RadiusAttribute::new_string(
                punglios::pppoe::auth::ATTR_FILTER_ID,
                val,
            ));

            let _ = punglios::pppoe::auth::parse_bandwidth_from_response(&pkt);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_phase2);
criterion_main!(benches);
