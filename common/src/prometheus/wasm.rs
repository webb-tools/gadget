use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub enum PrometheusConfig {
    Enabled { bind_addr: SocketAddr },
    Disabled,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self::Disabled
    }
}

pub async fn setup(_config: PrometheusConfig) -> Result<(), crate::Error> {
    Err(crate::Error::PrometheusError {
        err: "Prometheus is not yet supported on WASM targets".to_string(),
    })
}
