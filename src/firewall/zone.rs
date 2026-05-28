use crate::traits::FirewallZone;

pub fn default_zones() -> Vec<FirewallZone> {
    vec![
        FirewallZone {
            name: "lan".into(),
            interfaces: vec![],
            forward: Some(crate::traits::FirewallAction::Accept),
            input: Some(crate::traits::FirewallAction::Accept),
            output: Some(crate::traits::FirewallAction::Accept),
        },
        FirewallZone {
            name: "wan".into(),
            interfaces: vec![],
            forward: Some(crate::traits::FirewallAction::Drop),
            input: Some(crate::traits::FirewallAction::Drop),
            output: Some(crate::traits::FirewallAction::Accept),
        },
        FirewallZone {
            name: "vpn".into(),
            interfaces: vec![],
            forward: Some(crate::traits::FirewallAction::Accept),
            input: Some(crate::traits::FirewallAction::Drop),
            output: Some(crate::traits::FirewallAction::Accept),
        },
    ]
}
