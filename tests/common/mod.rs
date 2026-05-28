#![allow(dead_code)]

use punglios::traits::MockBackend;

pub fn create_mock_backend() -> MockBackend {
    MockBackend::new()
}

pub fn with_default_ifaces(backend: &MockBackend, names: &[&str]) {
    for name in names {
        backend.add_default_iface(name);
    }
}
