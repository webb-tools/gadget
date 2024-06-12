use alloy_primitives::Address;
use alloy_provider::Provider;

use eigen_contracts::RegistryCoordinator;

use crate::{el_contracts::ElChainContractManager, types::AvsError, Config};

pub mod reader;
pub mod subscriber;
pub mod writer;

pub type AvsRegistryContractResult<T> = Result<T, AvsError>;

#[derive(Clone)]
pub struct AvsRegistryContractManager<T: Config> {
    service_manager_addr: Address,
    bls_apk_registry_addr: Address,
    registry_coordinator_addr: Address,
    operator_state_retriever_addr: Address,
    stake_registry_addr: Address,
    eth_client_http: T::PH,
    eth_client_ws: T::PW,
    el_contract_manager: ElChainContractManager<T>,
    signer: T::S,
}

impl<T: Config> AvsRegistryContractManager<T> {
    pub async fn build(
        service_manager_addr: Address,
        registry_coordinator_addr: Address,
        operator_state_retriever_addr: Address,
        delegation_manager_addr: Address,
        avs_directory_addr: Address,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
    ) -> Result<Self, AvsError> {
        let registry_coordinator =
            RegistryCoordinator::new(registry_coordinator_addr, eth_client_http.clone());

        let bls_apk_registry_addr = registry_coordinator
            .blsApkRegistry()
            .call()
            .await
            .map(|addr| addr._0)?;

        let stake_registry_addr = registry_coordinator
            .stakeRegistry()
            .call()
            .await
            .map(|addr| addr._0)?;

        let el_contract_manager = ElChainContractManager::build(
            delegation_manager_addr,
            avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await?;

        Ok(AvsRegistryContractManager {
            service_manager_addr,
            bls_apk_registry_addr,
            registry_coordinator_addr,
            operator_state_retriever_addr,
            stake_registry_addr,
            eth_client_http,
            eth_client_ws,
            el_contract_manager,
            signer,
        })
    }
}
