use alloy_network::Ethereum;
use alloy_provider::Provider;
use alloy_signer::Signer;
use alloy_transport::Transport;

pub mod avs_registry;
pub mod crypto;
pub mod el_contracts;
pub mod node_api;
pub mod services;
pub mod types;
pub mod utils;

pub trait Config: Send + Sync + Clone + 'static {
    type TH: Transport + Clone + Send + Sync;
    type TW: Transport + Clone + Send + Sync;
    type PH: Provider<Self::TH, Ethereum> + Clone + Send + Sync;
    type PW: Provider<Self::TW, Ethereum> + Clone + Send + Sync;
    type S: Signer + Clone + Send + Sync;
}
