use crate::routing::{DynamicRoute, PrefixListEntry, AsPathFilter, RouteMapEntry};

pub struct RealRouteFilter {
    prefix_lists: Vec<PrefixListEntry>,
    as_path_filters: Vec<AsPathFilter>,
    route_maps: Vec<RouteMapEntry>,
}

impl RealRouteFilter {
    pub fn new() -> Self {
        Self {
            prefix_lists: Vec::new(),
            as_path_filters: Vec::new(),
            route_maps: Vec::new(),
        }
    }

    pub fn load_prefix_lists(&mut self, entries: Vec<PrefixListEntry>) {
        self.prefix_lists = entries;
    }

    pub fn load_as_path_filters(&mut self, filters: Vec<AsPathFilter>) {
        self.as_path_filters = filters;
    }

    pub fn load_route_maps(&mut self, maps: Vec<RouteMapEntry>) {
        self.route_maps = maps;
    }

    pub fn filter_route(&self, route: &DynamicRoute) -> FilterAction {
        // Check prefix lists
        let cidr = format!("{}/{}", route.destination, route.prefix);
        for entry in &self.prefix_lists {
            if entry.matches(&cidr, route.prefix) {
                return match entry.action {
                    crate::routing::PrefixListAction::Permit => FilterAction::Permit,
                    crate::routing::PrefixListAction::Deny => FilterAction::Deny,
                };
            }
        }
        FilterAction::Permit
    }

    pub fn apply_route_map(&self, route: &DynamicRoute) -> Option<RouteModifications> {
        for map in &self.route_maps {
            let prefix_match = map.match_prefix_list.as_ref().map_or(true, |name| {
                self.prefix_lists.iter().any(|pl| {
                    let cidr = format!("{}/{}", route.destination, route.prefix);
                    pl.name == *name && pl.matches(&cidr, route.prefix)
                })
            });

            if map.action == crate::routing::PrefixListAction::Deny && prefix_match {
                return None;
            }

            if prefix_match {
                let mut mods = RouteModifications::default();
                for action in &map.set_actions {
                    match action {
                        crate::routing::SetAction::LocalPref(v) => mods.local_pref = Some(*v),
                        crate::routing::SetAction::Metric(v) => mods.metric = Some(*v),
                        _ => {}
                    }
                }
                return Some(mods);
            }
        }
        Some(RouteModifications::default())
    }
}

impl Default for RealRouteFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RouteModifications {
    pub local_pref: Option<u32>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Permit,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{PrefixListAction, RoutingProtocol};

    fn make_route(dst: &str, prefix: u8) -> DynamicRoute {
        DynamicRoute {
            destination: dst.to_string(),
            prefix,
            nexthop: "10.0.0.1".into(),
            metric: 0,
            protocol: RoutingProtocol::Bgp,
            age_secs: 0,
            interface: None,
        }
    }

    #[test]
    fn test_prefix_filter_deny() {
        let mut filter = RealRouteFilter::new();
        filter.load_prefix_lists(vec![PrefixListEntry {
            name: "block-local".into(),
            seq: 10,
            action: PrefixListAction::Deny,
            prefix: "10.0.0.0/8".into(),
            ge: None,
            le: None,
            description: None,
        }]);
        let route = make_route("10.0.0.0", 8);
        assert_eq!(filter.filter_route(&route), FilterAction::Deny);
    }

    #[test]
    fn test_prefix_filter_permit() {
        let mut filter = RealRouteFilter::new();
        filter.load_prefix_lists(vec![PrefixListEntry {
            name: "allow-default".into(),
            seq: 10,
            action: PrefixListAction::Permit,
            prefix: "0.0.0.0/0".into(),
            ge: None,
            le: None,
            description: None,
        }]);
        let route = make_route("0.0.0.0", 0);
        assert_eq!(filter.filter_route(&route), FilterAction::Permit);
    }
}
