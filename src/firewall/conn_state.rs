use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
    Untracked,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Related => "related",
            Self::Invalid => "invalid",
            Self::Untracked => "untracked",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "new" => Some(Self::New),
            "established" => Some(Self::Established),
            "related" => Some(Self::Related),
            "invalid" => Some(Self::Invalid),
            "untracked" => Some(Self::Untracked),
            _ => None,
        }
    }

    pub fn allows_reply(&self) -> bool {
        matches!(self, Self::Established | Self::Related)
    }

    pub fn needs_conntrack(&self) -> bool {
        !matches!(self, Self::Untracked)
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnStateFilter {
    pub states: Vec<ConnectionState>,
    pub invert: bool,
}

impl ConnStateFilter {
    pub fn new(states: Vec<ConnectionState>) -> Self {
        Self {
            states,
            invert: false,
        }
    }

    pub fn matches(&self, state: &ConnectionState) -> bool {
        let matched = self.states.contains(state);
        if self.invert { !matched } else { matched }
    }
}

impl Default for ConnStateFilter {
    fn default() -> Self {
        Self {
            states: vec![ConnectionState::Established, ConnectionState::Related],
            invert: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_roundtrip() {
        for state in &[
            ConnectionState::New,
            ConnectionState::Established,
            ConnectionState::Related,
            ConnectionState::Invalid,
            ConnectionState::Untracked,
        ] {
            assert_eq!(
                ConnectionState::from_str(state.as_str()),
                Some(*state)
            );
        }
    }

    #[test]
    fn test_allows_reply() {
        assert!(ConnectionState::Established.allows_reply());
        assert!(ConnectionState::Related.allows_reply());
        assert!(!ConnectionState::New.allows_reply());
        assert!(!ConnectionState::Invalid.allows_reply());
    }

    #[test]
    fn test_filter_matches() {
        let filter = ConnStateFilter::new(vec![ConnectionState::Established]);
        assert!(filter.matches(&ConnectionState::Established));
        assert!(!filter.matches(&ConnectionState::New));
    }

    #[test]
    fn test_inverted_filter() {
        let mut filter = ConnStateFilter::new(vec![ConnectionState::Invalid]);
        filter.invert = true;
        assert!(filter.matches(&ConnectionState::New));
        assert!(!filter.matches(&ConnectionState::Invalid));
    }
}
