#[cfg(feature = "real")]
use anyhow::{Context, Result, bail};
#[cfg(feature = "real")]
use async_trait::async_trait;
#[cfg(feature = "real")]
use nlink::netlink::link::{BridgeLink, DummyLink, VlanLink};
#[cfg(feature = "real")]
use nlink::netlink::messages::RouteMessage;
#[cfg(feature = "real")]
use nlink::netlink::nftables::{Chain, ChainType, Family, Hook, Policy, Priority, Rule};
#[cfg(feature = "real")]
use std::net::{IpAddr, Ipv4Addr};

use crate::traits::netlink::Route as PungliRoute;
use crate::traits::netlink::*;

// ─── RealBackend ─────────────────────────────────────

#[cfg(feature = "real")]
pub struct RealBackend {
    rt_conn: Connection<nlink::netlink::Route>,
    nf_conn: Connection<Nftables>,
}

#[cfg(feature = "real")]
impl RealBackend {
    pub fn new() -> Result<Self> {
        Ok(Self {
            rt_conn: Connection::<nlink::netlink::Route>::new()
                .context("failed to open RTNetlink connection")?,
            nf_conn: Connection::<Nftables>::new()
                .context("failed to open nftables netlink connection")?,
        })
    }
}

// ─── NetlinkIfaces ────────────────────────────────────

#[cfg(feature = "real")]
fn link_to_interface(link: &nlink::netlink::messages::LinkMessage) -> Interface {
    let name = link.name_or("unknown").to_string();
    let mac_addr = link.address().unwrap_or(&[0u8; 0]);
    let mac: [u8; 6] = if mac_addr.len() >= 6 {
        let mut m = [0u8; 6];
        m.copy_from_slice(&mac_addr[..6]);
        m
    } else {
        [0u8; 6]
    };
    Interface {
        name,
        index: link.ifindex(),
        mac,
        addresses: vec![],
        mtu: {
            let v = link.mtu().unwrap_or(0) as u16;
            if v == 0 {
                tracing::warn!("no MTU reported for link, defaulting to 1500");
                1500
            } else {
                v
            }
        },
        up: link.is_up(),
    }
}

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkIfaces for RealBackend {
    async fn list(&self) -> Result<Vec<Interface>> {
        let links = self.rt_conn.get_links().await?;
        Ok(links.iter().map(link_to_interface).collect())
    }

    async fn get(&self, name: &str) -> Result<Interface> {
        let link = self
            .rt_conn
            .get_link_by_name(name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("interface '{name}' not found"))?;
        Ok(link_to_interface(&link))
    }

    async fn create(&self, config: &InterfaceConfig) -> Result<Interface> {
        use nlink::netlink::link::LinkConfig;

        match config.kind {
            Some(InterfaceKind::Bridge) => {
                self.rt_conn
                    .add_link(BridgeLink::new(&config.name))
                    .await
                    .context(format!("create bridge '{}'", config.name))?;
            }
            Some(InterfaceKind::Vlan {
                ref parent,
                vlan_id,
            }) => {
                self.rt_conn
                    .add_link(VlanLink::new(&config.name, parent).vlan_id(vlan_id))
                    .await
                    .context(format!("create vlan '{}.{}'", parent, config.name))?;
            }
            _ => {
                // Dummy is the default fallback
                self.rt_conn
                    .add_link(DummyLink::new(&config.name))
                    .await
                    .context(format!("create dummy '{}'", config.name))?;
            }
        }

        if let Some(mtu) = config.mtu {
            self.rt_conn
                .set_link_mtu(&config.name, mtu as u32)
                .await
                .context("set mtu")?;
        }

        self.rt_conn
            .set_link_up(&config.name)
            .await
            .context("set up")?;

        for addr in &config.addresses {
            self.add_address(&config.name, *addr)
                .await
                .context("add address")?;
        }

        if let Some(ref bridge) = config.bridge {
            self.rt_conn
                .enslave(&config.name, bridge)
                .await
                .context("enslave to bridge")?;
        }

        let link = self
            .rt_conn
            .get_link_by_name(&config.name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("interface created but not found"))?;
        Ok(link_to_interface(&link))
    }

    async fn delete(&self, name: &str) -> Result<()> {
        self.rt_conn
            .del_link(name)
            .await
            .context(format!("delete interface '{name}'"))
    }

    async fn set_up(&self, name: &str) -> Result<()> {
        self.rt_conn.set_link_up(name).await?;
        Ok(())
    }

    async fn set_down(&self, name: &str) -> Result<()> {
        self.rt_conn.set_link_down(name).await?;
        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u16) -> Result<()> {
        self.rt_conn.set_link_mtu(name, mtu as u32).await?;
        Ok(())
    }

    async fn add_address(&self, name: &str, addr: IpAddr) -> Result<()> {
        match addr {
            IpAddr::V4(v4) => {
                let config = nlink::netlink::addr::Ipv4Address::new(name, v4, 24);
                self.rt_conn.add_address(config).await?;
            }
            IpAddr::V6(v6) => {
                let config = nlink::netlink::addr::Ipv6Address::new(name, v6, 64);
                self.rt_conn.add_address(config).await?;
            }
        }
        Ok(())
    }
}

// ─── NetlinkFirewall ──────────────────────────────────

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkFirewall for RealBackend {
    async fn list_rules(&self, zone: &str) -> Result<Vec<FirewallRule>> {
        let rules = self.nf_conn.list_rules(zone, Family::Inet).await?;
        Ok(rules
            .iter()
            .map(|ri| FirewallRule {
                handle: ri.handle,
                zone: zone.to_string(),
                chain: ri.chain.clone(),
                protocol: None,
                src_addr: None,
                dst_addr: None,
                src_port: None,
                dst_port: None,
                action: FirewallAction::Accept,
                position: 0,
            })
            .collect())
    }

    async fn add_rule(&self, rule: &FirewallRule) -> Result<u64> {
        let table = "punglios";
        let mut nf_rule = Rule::new(table, &rule.zone).family(Family::Inet);

        if let Some(port) = rule.dst_port {
            nf_rule = nf_rule.match_tcp_dport(port);
        }

        let _handle = match rule.action {
            FirewallAction::Accept => self.nf_conn.add_rule(nf_rule.accept()).await?,
            FirewallAction::Drop => self.nf_conn.add_rule(nf_rule.drop()).await?,
            FirewallAction::Reject => self.nf_conn.add_rule(nf_rule.reject()).await?,
            FirewallAction::Jump(ref target) => self.nf_conn.add_rule(nf_rule.goto(target)).await?,
        };

        Ok(rule.handle)
    }

    async fn delete_rule(&self, handle: u64) -> Result<()> {
        self.nf_conn
            .del_rule("punglios", "default", Family::Inet, handle)
            .await?;
        Ok(())
    }

    async fn flush_rules(&self) -> Result<()> {
        self.nf_conn.flush_table("punglios", Family::Inet).await?;
        Ok(())
    }

    async fn create_zone(&self, zone: &FirewallZone) -> Result<()> {
        let hook = Hook::Forward;
        let chain = Chain::new("punglios", &zone.name)
            .family(Family::Inet)
            .hook(hook)
            .priority(Priority::Filter)
            .policy(Policy::Accept)
            .chain_type(ChainType::Filter);
        self.nf_conn.add_chain(chain).await?;
        Ok(())
    }
}

// ─── NetlinkQos ───────────────────────────────────────

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkQos for RealBackend {
    async fn add_qdisc(&self, config: &QdiscConfig) -> Result<()> {
        let qdisc = nlink::netlink::tc::HtbQdiscConfig::new();
        self.rt_conn.add_qdisc(&config.iface, qdisc).await?;
        Ok(())
    }

    async fn delete_qdisc(&self, iface: &str, _handle: u32) -> Result<()> {
        let parent = nlink::netlink::tc_handle::TcHandle::from_raw(0);
        self.rt_conn.del_qdisc(iface, parent).await?;
        Ok(())
    }

    async fn add_class(&self, config: &ClassConfig) -> Result<()> {
        let rate_str = format!("{}kbps", config.rate);
        let ceil_str = format!("{}kbps", config.ceil);
        let rate: nlink::util::Rate = rate_str.parse().context("invalid rate")?;
        let ceil: nlink::util::Rate = ceil_str.parse().context("invalid ceil")?;
        let parent = nlink::netlink::tc_handle::TcHandle::from_raw(config.parent);
        let classid = nlink::netlink::tc_handle::TcHandle::from_raw(config.classid);
        let htb = nlink::netlink::tc::HtbClassConfig::new(rate).ceil(ceil);
        self.rt_conn
            .add_class(&config.iface, parent, classid, htb)
            .await?;
        Ok(())
    }

    async fn delete_class(&self, iface: &str, classid: u32) -> Result<()> {
        let handle = nlink::netlink::tc_handle::TcHandle::from_raw(classid);
        let parent = nlink::netlink::tc_handle::TcHandle::from_raw(0);
        self.rt_conn.del_class(iface, handle, parent).await?;
        Ok(())
    }
}

// ─── NetlinkConntrack ─────────────────────────────────

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkConntrack for RealBackend {
    async fn count(&self) -> Result<usize> {
        let s = std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count")?;
        Ok(s.trim().parse()?)
    }

    async fn list(&self) -> Result<Vec<ConntrackEntry>> {
        let content = std::fs::read_to_string("/proc/net/nf_conntrack")
            .context("failed to read /proc/net/nf_conntrack")?;
        let mut entries = Vec::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let state = parts.first().unwrap_or(&"?").to_string();
            let src_port = parts
                .get(5)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            entries.push(ConntrackEntry {
                protocol: match parts.get(2).unwrap_or(&"0").as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    _ => 0,
                },
                src: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                dst: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                sport: src_port,
                dport: 0,
                state,
                bytes: 0,
                packets: 0,
                timeout: 0,
            });
        }
        Ok(entries)
    }

    async fn flush(&self) -> Result<()> {
        tokio::task::spawn_blocking(|| {
            std::fs::write("/proc/sys/net/netfilter/nf_conntrack_max", "0")?;
            std::thread::sleep(std::time::Duration::from_millis(10));
            std::fs::write("/proc/sys/net/netfilter/nf_conntrack_max", "262144")
        })
        .await
        .map_err(|e| anyhow::anyhow!("flush task failed: {e}"))?
        .map_err(|e| anyhow::anyhow!("flush failed: {e}"))?;
        Ok(())
    }

    async fn set_max(&self, max: u32) -> Result<()> {
        let val = max.to_string();
        tokio::task::spawn_blocking(move || {
            std::fs::write("/proc/sys/net/netfilter/nf_conntrack_max", &val)
        })
        .await
        .map_err(|e| anyhow::anyhow!("set_max task failed: {e}"))?
        .map_err(|e| anyhow::anyhow!("set_max failed: {e}"))?;
        Ok(())
    }

    async fn set_buckets(&self, _buckets: u32) -> Result<()> {
        bail!("conntrack hashsize set at module load time only")
    }
}

// ─── NetlinkNat ───────────────────────────────────────

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkNat for RealBackend {
    async fn add_rule(&self, rule: &NatRule) -> Result<u64> {
        let chain = match rule.kind {
            NatKind::Snat | NatKind::Masquerade => "postrouting",
            NatKind::Dnat => "prerouting",
        };
        let nf_rule = Rule::new("punglios-nat", chain).family(Family::Inet);
        match rule.kind {
            NatKind::Masquerade => self.nf_conn.add_rule(nf_rule.masquerade()).await?,
            NatKind::Snat => {
                if let Some(addr) = rule.to_addr {
                    match addr {
                        IpAddr::V4(v4) => self.nf_conn.add_rule(nf_rule.snat(v4, None)).await?,
                        IpAddr::V6(_) => bail!("IPv6 NAT not supported"),
                    }
                } else {
                    self.nf_conn.add_rule(nf_rule.masquerade()).await?
                }
            }
            NatKind::Dnat => {
                if let Some(addr) = rule.to_addr {
                    match addr {
                        IpAddr::V4(v4) => self.nf_conn.add_rule(nf_rule.dnat(v4, None)).await?,
                        IpAddr::V6(_) => bail!("IPv6 NAT not supported"),
                    }
                } else {
                    self.nf_conn.add_rule(nf_rule.masquerade()).await?
                }
            }
        }
        Ok(rule.handle)
    }

    async fn delete_rule(&self, handle: u64) -> Result<()> {
        let r1 = self
            .nf_conn
            .del_rule("punglios-nat", "postrouting", Family::Inet, handle)
            .await;
        if r1.is_ok() {
            return Ok(());
        }
        self.nf_conn
            .del_rule("punglios-nat", "prerouting", Family::Inet, handle)
            .await?;
        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<NatRule>> {
        bail!("NAT rule listing not implemented")
    }
}

// ─── NetlinkRoute ─────────────────────────────────────

#[cfg(feature = "real")]
fn route_message_to_route(msg: &RouteMessage) -> PungliRoute {
    let dst = msg.destination().copied().unwrap_or_else(|| {
        tracing::warn!("route has no destination, using UNSPECIFIED");
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    });
    PungliRoute {
        destination: dst,
        prefix: msg.dst_len(),
        nexthop: msg.gateway().copied(),
        iface: msg.oif().map(|_| "unknown".to_string()),
        metric: msg.priority(),
    }
}

#[cfg(feature = "real")]
#[async_trait]
impl NetlinkRoute for RealBackend {
    async fn add_route(&self, route: &PungliRoute) -> Result<()> {
        let dst_str = route.destination.to_string();
        let mut builder = nlink::netlink::route::Ipv4Route::new(dst_str, route.prefix);
        if let Some(ref nh) = route.nexthop {
            if let IpAddr::V4(v4) = nh {
                builder = builder.gateway(*v4);
            }
        }
        if let Some(ref iface) = route.iface {
            builder = builder.dev(iface);
        }
        self.rt_conn.add_route(builder).await?;
        Ok(())
    }

    async fn delete_route(&self, destination: IpAddr, prefix: u8) -> Result<()> {
        if let IpAddr::V4(v4) = destination {
            let route = nlink::netlink::route::Ipv4Route::new(v4.to_string(), prefix);
            self.rt_conn.del_route(route).await?;
        }
        Ok(())
    }

    async fn list_routes(&self) -> Result<Vec<PungliRoute>> {
        let msgs = self.rt_conn.get_routes().await?;
        Ok(msgs.iter().map(route_message_to_route).collect())
    }
}
