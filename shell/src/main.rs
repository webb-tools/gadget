use color_eyre::Result;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::IpAddr, path::PathBuf, str::FromStr};
use structopt::StructOpt;

mod config;
mod keystore;
mod network;
mod shell;
mod tangle;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Gadget",
    about = "An MPC executor that connects to the Tangle network to perform work"
)]
struct Opt {
    /// The path to the configuration file. If not provided, the default configuration will be used.
    /// Note that if the configuration file is provided, the command line arguments will be ignored.
    #[structopt(global = true, parse(from_os_str), short = "c", long = "config")]
    config: Option<PathBuf>,
    /// The verbosity level, can be used multiple times
    #[structopt(long, short = "v", global = true, parse(from_occurrences))]
    verbose: i32,
    /// Whether to use pretty logging
    #[structopt(global = true, long)]
    pretty: bool,
    /// The options for the shell
    #[structopt(flatten)]
    options: TomlConfig,
}

#[derive(Default, Debug, StructOpt, Serialize, Deserialize)]
#[structopt(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
enum SupportedChains {
    #[default]
    LocalTestnet,
    LocalMainnet,
    Testnet,
    Mainnet,
}

#[derive(Debug, StructOpt, Serialize, Deserialize)]
struct TomlConfig {
    /// The IP address to bind to for the libp2p node.
    #[structopt(long = "bind-ip", short = "i", default_value = defaults::BIND_IP)]
    #[serde(default = "defaults::bind_ip")]
    bind_ip: IpAddr,
    /// The port to bind to for the libp2p node.
    #[structopt(long = "port", short = "p", default_value = defaults::BIND_PORT)]
    #[serde(default = "defaults::bind_port")]
    bind_port: u16,
    /// The RPC URL of the Tangle Node.
    #[structopt(long = "url", parse(try_from_str = url::Url::parse), default_value = defaults::RPC_URL)]
    #[serde(default = "defaults::rpc_url")]
    url: url::Url,
    /// The List of bootnodes to connect to
    #[structopt(long = "bootnodes", parse(try_from_str = <Multiaddr as std::str::FromStr>::from_str))]
    #[serde(default)]
    bootnodes: Vec<Multiaddr>,
    /// The node key in hex format. If not provided, a random node key will be generated.
    #[structopt(long = "node-key", env, parse(try_from_str = parse_node_key))]
    #[serde(skip_serializing)]
    node_key: Option<String>,
    /// The base path to store the shell data, and read data from the keystore.
    #[structopt(
        parse(from_os_str),
        long,
        short = "d",
        required_unless = "config",
        default_value_if("config", None, ".")
    )]
    base_path: PathBuf,
    /// Keystore Password, if not provided, the password will be read from the environment variable.
    #[structopt(long = "keystore-password", env)]
    keystore_password: Option<String>,
    /// The chain to connect to, must be one of the supported chains.
    #[structopt(
        long,
        default_value,
        possible_values = &[
            "local_testnet",
            "local_mainnet",
            "testnet",
            "mainnet"
        ]
    )]
    #[serde(default)]
    chain: SupportedChains,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let opt = Opt::from_args();
    setup_logger(&opt, "gadget_shell")?;
    let config = if let Some(config) = opt.config {
        let config_contents = std::fs::read_to_string(config)?;
        toml::from_str(&config_contents)?
    } else {
        opt.options
    };
    shell::run_forever(config::ShellConfig {
        keystore: config::KeystoreConfig::Path {
            path: config
                .base_path
                .join("chains")
                .join(config.chain.to_string())
                .join("keystore"),
            password: config.keystore_password.map(|s| s.into()),
        },
        subxt: config::SubxtConfig {
            endpoint: config.url,
        },
        base_path: config.base_path,
        bind_ip: config.bind_ip,
        bind_port: config.bind_port,
        bootnodes: config.bootnodes,
        node_key: hex::decode(
            config
                .node_key
                .unwrap_or_else(|| hex::encode(defaults::generate_node_key())),
        )?
        .try_into()
        .map_err(|_| {
            color_eyre::eyre::eyre!("Invalid node key length, expect 32 bytes hex string")
        })?,
    })
    .await?;
    Ok(())
}

/// Sets up the logger for the shell, based on the verbosity level passed in.
fn setup_logger(opt: &Opt, filter: &str) -> Result<()> {
    use tracing::Level;
    let log_level = match opt.verbose {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(format!("{filter}={log_level}").parse()?)
        .add_directive(format!("gadget={log_level}").parse()?);
    let logger = tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_line_number(false)
        .without_time()
        .with_max_level(log_level)
        .with_env_filter(env_filter);
    if opt.pretty {
        logger.pretty().init();
    } else {
        logger.compact().init();
    }
    Ok(())
}

mod defaults {
    pub const BIND_PORT: &str = "30555";
    pub const BIND_IP: &str = "0.0.0.0";
    pub const RPC_URL: &str = "ws://127.0.0.1:9944";

    pub fn rpc_url() -> url::Url {
        url::Url::parse(RPC_URL).expect("Default RPC URL is valid")
    }

    pub fn bind_ip() -> std::net::IpAddr {
        BIND_IP.parse().expect("Default bind IP is valid")
    }

    pub fn bind_port() -> u16 {
        BIND_PORT.parse().expect("Default bind port is valid")
    }

    /// Generates a random node key
    pub fn generate_node_key() -> [u8; 32] {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut array = [0u8; 32];
        rng.fill(&mut array);
        array
    }
}

fn parse_node_key(s: &str) -> Result<String> {
    let result: [u8; 32] = hex::decode(s.replace("0x", ""))?.try_into().map_err(|_| {
        color_eyre::eyre::eyre!("Invalid node key length, expect 32 bytes hex string")
    })?;
    Ok(hex::encode(result))
}

impl FromStr for SupportedChains {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "local_testnet" => Ok(SupportedChains::LocalTestnet),
            "local_mainnet" => Ok(SupportedChains::LocalMainnet),
            "testnet" => Ok(SupportedChains::Testnet),
            "mainnet" => Ok(SupportedChains::Mainnet),
            _ => Err(format!("Invalid chain: {}", s)),
        }
    }
}

impl Display for SupportedChains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedChains::LocalTestnet => write!(f, "local_testnet"),
            SupportedChains::LocalMainnet => write!(f, "local_mainnet"),
            SupportedChains::Testnet => write!(f, "testnet"),
            SupportedChains::Mainnet => write!(f, "mainnet"),
        }
    }
}
