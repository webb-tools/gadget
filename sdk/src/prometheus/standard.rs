use crate::error::Error;
use crate::metrics;
use crate::prometheus::shared::{BYTES_RECEIVED, BYTES_SENT, REGISTRY};
use alloc::string::ToString;
use core::net::SocketAddr;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};

/// The configuration for the Prometheus metrics server.
///
/// By [default](Self::default), the Prometheus metrics server is enabled and listens on `0.0.0.0:9615`.
#[derive(Debug, Clone, Copy)]
pub enum PrometheusConfig {
    Enabled { bind_addr: SocketAddr },
    Disabled,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self::Enabled {
            bind_addr: SocketAddr::from_str("0.0.0.0:9615").unwrap(),
        }
    }
}

/// Set up the Prometheus metrics server.
///
/// # Errors
///
/// * Any of the metrics could not be registered.
/// * The HTTP server could not be initialized.
pub async fn setup(config: PrometheusConfig) -> Result<(), Error> {
    let PrometheusConfig::Enabled { bind_addr } = config else {
        return Ok(());
    };

    static HAS_REGISTERED: AtomicBool = AtomicBool::new(false);
    if HAS_REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    HAS_REGISTERED.store(true, Ordering::SeqCst);

    let _ =
        metrics::register(BYTES_RECEIVED.clone(), &REGISTRY).map_err(|err| Error::Prometheus {
            err: err.to_string(),
        })?;

    let _ = metrics::register(BYTES_SENT.clone(), &REGISTRY).map_err(|err| Error::Prometheus {
        err: err.to_string(),
    })?;

    metrics::init_prometheus(bind_addr, REGISTRY.clone())
        .await
        .map_err(|err| Error::Prometheus {
            err: err.to_string(),
        })?;

    Ok(())
}
