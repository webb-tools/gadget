use std::path::PathBuf;

use color_eyre::{eyre::Context, Result};

#[derive(Debug, Clone)]
struct GadgetEnvironment {
    tangle_rpc_endpoint: String,
    keystore_uri: String,
    data_dir: PathBuf,
    blueprint_id: u64,
    service_id: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let gadget_env = GadgetEnvironment::from_env()?;
    println!("{:?}", gadget_env);
    Ok(())
}

impl GadgetEnvironment {
    /// Create a new Operator from the environment.
    fn from_env() -> Result<Self> {
        Ok(Self {
            tangle_rpc_endpoint: std::env::var("RPC_URL").context("loading RPC_URL from env")?,
            keystore_uri: std::env::var("KEYSTORE_URI").context("loading KEYSTORE_URI from env")?,
            data_dir: std::env::var("DATA_DIR")
                .context("loading DATA_DIR from env")?
                .into(),
            blueprint_id: std::env::var("BLUEPRINT_ID")
                .context("loading BLUEPRINT_ID from env")?
                .parse()
                .context("parsing BLUEPRINT_ID not a u64")?,
            service_id: std::env::var("SERVICE_ID")
                .context("loading SERVICE_ID from env")?
                .parse()
                .context("parsing SERVICE_ID not a u64")?,
        })
    }
}