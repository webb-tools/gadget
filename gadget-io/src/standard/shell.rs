use color_eyre::Result;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::IpAddr, path::PathBuf, str::FromStr};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Gadget",
    about = "An MPC executor that connects to the Tangle network to perform work"
)]
pub struct Opt {
    /// The path to the configuration file. If not provided, the default configuration will be used.
    /// Note that if the configuration file is provided, the command line arguments will be ignored.
    #[structopt(global = true, parse(from_os_str), short = "c", long = "config")]
    pub config: Option<PathBuf>,
    /// The verbosity level, can be used multiple times
    #[structopt(long, short = "v", global = true, parse(from_occurrences))]
    pub verbose: i32,
    /// Whether to use pretty logging
    #[structopt(global = true, long)]
    pub pretty: bool,
    /// The options for the shell
    #[structopt(flatten)]
    pub options: GadgetConfig,
}

#[derive(Copy, Clone, Default, Debug, StructOpt, Serialize, Deserialize)]
#[structopt(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SupportedChains {
    #[default]
    LocalTestnet,
    LocalMainnet,
    Testnet,
    Mainnet,
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

#[derive(Debug, StructOpt, Serialize, Deserialize)]
/// All shells should expect this as CLI input. The Shell Manager will be responsible for passing these values to the shell.
pub struct GadgetConfig {
    /// The IP address to bind to for the libp2p node.
    #[structopt(long = "bind-ip", short = "i", default_value = defaults::BIND_IP)]
    #[serde(default = "defaults::bind_ip")]
    pub bind_ip: IpAddr,
    /// The port to bind to for the libp2p node.
    #[structopt(long = "port", short = "p", default_value = defaults::BIND_PORT)]
    #[serde(default = "defaults::bind_port")]
    pub bind_port: u16,
    /// The RPC URL of the Tangle Node.
    #[structopt(long = "url", parse(try_from_str = url::Url::parse), default_value = defaults::RPC_URL)]
    #[serde(default = "defaults::rpc_url")]
    pub url: url::Url,
    /// The List of bootnodes to connect to
    #[structopt(long = "bootnodes", parse(try_from_str = <Multiaddr as std::str::FromStr>::from_str))]
    #[serde(default)]
    pub bootnodes: Vec<Multiaddr>,
    /// The node key in hex format. If not provided, a random node key will be generated.
    #[structopt(long = "node-key", env, parse(try_from_str = parse_node_key))]
    #[serde(skip_serializing)]
    pub node_key: Option<String>,
    /// The base path to store the shell-sdk data, and read data from the keystore.
    #[structopt(
        parse(from_os_str),
        long,
        short = "d",
        required_unless = "config",
        default_value_if("config", None, ".")
    )]
    pub base_path: PathBuf,
    /// Keystore Password, if not provided, the password will be read from the environment variable.
    #[structopt(long = "keystore-password", env)]
    pub keystore_password: Option<String>,
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
    pub chain: SupportedChains,
    /// The verbosity level, can be used multiple times
    #[structopt(long, short = "v", global = true, parse(from_occurrences))]
    pub verbose: i32,
    /// Whether to use pretty logging
    #[structopt(global = true, long)]
    pub pretty: bool,
}

pub mod defaults {
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
