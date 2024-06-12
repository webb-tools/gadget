use alloy_primitives::Address;
use alloy_provider::Provider;

use eigen_contracts::DelegationManager;

use crate::{types::AvsError, Config};

pub mod reader;
pub mod writer;

#[derive(Clone)]
pub struct ElChainContractManager<T: Config> {
    slasher_addr: Address,
    delegation_manager_addr: Address,
    strategy_manager_addr: Address,
    avs_directory_addr: Address,
    eth_client_http: T::PH,
    eth_client_ws: T::PW,
    signer: T::S,
}

impl<T: Config> ElChainContractManager<T> {
    pub async fn build(
        delegation_manager_addr: Address,
        avs_directory_addr: Address,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
    ) -> Result<Self, AvsError> {
        let delegation_manager =
            DelegationManager::new(delegation_manager_addr, eth_client_http.clone());
        let slasher_addr = delegation_manager.slasher().call().await.map(|a| a._0)?;
        let strategy_manager_addr = delegation_manager
            .strategyManager()
            .call()
            .await
            .map(|a| a._0)?;

        Ok(ElChainContractManager {
            slasher_addr,
            delegation_manager_addr,
            strategy_manager_addr,
            avs_directory_addr,
            eth_client_http,
            eth_client_ws,
            signer,
        })
    }
}
