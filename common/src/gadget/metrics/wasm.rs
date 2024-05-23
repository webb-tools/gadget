#![allow(dead_code)]
use prometheus::{Counter, Registry};

pub struct Metrics {
    registered_messages: Counter,
    expired_messages: Counter,
}

impl Metrics {
    fn register(_registry: &Registry) -> Result<Self, crate::Error> {
        Err(crate::Error::PrometheusError {
            err: "Prometheus is not yet supported on WASM targets".to_string(),
        })
    }
}
