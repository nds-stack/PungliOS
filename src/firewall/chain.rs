pub enum Chain {
    Input,
    Forward,
    Output,
    Custom(String),
}

impl Chain {
    pub fn name(&self) -> &str {
        match self {
            Self::Input => "input",
            Self::Forward => "forward",
            Self::Output => "output",
            Self::Custom(s) => s,
        }
    }
}

pub const DEFAULT_CHAINS: &[&str] = &["input", "forward", "output"];

pub fn default_chains() -> Vec<String> {
    DEFAULT_CHAINS.iter().map(|&s| s.to_string()).collect()
}
