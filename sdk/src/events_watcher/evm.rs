//! EVM Event Watcher Module

use crate::events_watcher::error::Error;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::FixedBytes;
use alloy_provider::{
    fillers::{ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller},
    Identity, Provider, ProviderBuilder, RootProvider, WsConnect,
};
use alloy_sol_types::SolEvent;
use alloy_transport::{BoxTransport, Transport};
use alloy_transport_http::{Client, Http};
use std::ops::Deref;

pub trait Config: Send + Sync + Clone + 'static {
    type TH: Transport + Clone + Send + Sync;
    type PH: Provider<Self::TH, Ethereum> + Clone + Send + Sync;
}

#[derive(Debug, Copy, Clone)]
pub struct DefaultNodeConfig {}

impl Config for DefaultNodeConfig {
    type TH = Http<Client>;
    type PH = FillProvider<
        JoinFill<
            JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
            WalletFiller<EthereumWallet>,
        >,
        RootProvider<Http<Client>>,
        Http<Client>,
        Ethereum,
    >;
}

pub trait EvmContract<T: Config>:
    Deref<Target = alloy_contract::ContractInstance<T::TH, T::PH, Ethereum>>
    + Send
    + Clone
    + Sync
    + 'static
{
}
impl<
        T: Config,
        X: Deref<Target = alloy_contract::ContractInstance<T::TH, T::PH, Ethereum>>
            + Send
            + Clone
            + Sync
            + 'static,
    > EvmContract<T> for X
{
}

pub trait EvmEvent: SolEvent + Clone + Send + Sync + 'static {}
impl<X: SolEvent + Clone + Send + Sync + 'static> EvmEvent for X {}

/// A trait for watching events from a contract.
/// EventWatcher trait exists for deployments that are smart-contract / EVM based
#[async_trait::async_trait]
pub trait EvmEventHandler<T: Config>: Send + Sync + 'static {
    /// The type of event this handler is for.
    type Event: EvmEvent;
    /// The genesis transaction hash for the contract.
    const GENESIS_TX_HASH: FixedBytes<32>;
    /// Handle a log event.
    async fn handle(&self, log: &alloy_rpc_types::Log, event: &Self::Event) -> Result<(), Error>;
}

pub fn get_provider_http(http_endpoint: &str) -> RootProvider<BoxTransport> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(http_endpoint.parse().unwrap())
        .root()
        .clone()
        .boxed();

    provider
}

pub fn get_wallet_provider_http(
    http_endpoint: &str,
    wallet: EthereumWallet,
) -> RootProvider<BoxTransport> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(http_endpoint.parse().unwrap())
        .root()
        .clone()
        .boxed();

    provider
}

pub async fn get_provider_ws(ws_endpoint: &str) -> RootProvider<BoxTransport> {
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(WsConnect::new(ws_endpoint))
        .await
        .unwrap()
        .root()
        .clone()
        .boxed();

    provider
}
