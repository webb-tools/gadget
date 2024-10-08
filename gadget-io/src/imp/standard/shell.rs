use crate::shared::shell::SupportedChains;
use multiaddr::Multiaddr;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};
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

#[derive(Debug, StructOpt, Serialize, Deserialize)]
/// All shells should expect this as CLI input. The Blueprint Manager will be responsible for passing these values to this gadget binary
pub struct GadgetConfig {
    /// The IP address to bind to for the libp2p node.
    #[structopt(long = "bind-ip", short = "i", default_value = defaults::BIND_IP)]
    #[serde(default = "defaults::bind_ip")]
    pub bind_addr: IpAddr,
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
    /// The base path to store the blueprint manager data, and read data from the keystore.
    #[structopt(long, short = "d")]
    pub keystore_uri: String,
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
}
