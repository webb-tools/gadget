use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use async_trait::async_trait;
use eigen_contracts::OperatorStateRetriever;
use futures::TryFutureExt;
use std::collections::HashMap;

use crate::{
    avs_registry::{reader::AvsRegistryChainReaderTrait, AvsRegistryContractManager},
    types::{AvsError, OperatorAvsState, OperatorId, OperatorInfo, QuorumAvsState, QuorumNum},
    Config,
};

use super::operator_info::OperatorInfoServiceTrait;

pub mod chain_caller;

#[async_trait]
pub trait AvsRegistryServiceTrait: Send + Sync + Clone + 'static {
    async fn get_operators_avs_state_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> Result<HashMap<OperatorId, OperatorAvsState>, AvsError>;

    async fn get_quorums_avs_state_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> Result<HashMap<QuorumNum, QuorumAvsState>, AvsError>;

    async fn get_check_signatures_indices(
        &self,
        reference_block_number: u64,
        quorum_numbers: Bytes,
        non_signer_operator_ids: Vec<FixedBytes<32>>,
    ) -> Result<OperatorStateRetriever::CheckSignaturesIndices, AvsError>;
}

#[derive(Clone)]
pub struct AvsRegistryServiceChainCaller<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    avs_registry_manager: AvsRegistryContractManager<T>,
    operator_info_service: I,
}

impl<T, I> AvsRegistryServiceChainCaller<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    pub async fn build(
        service_manager_addr: Address,
        registry_coordinator_addr: Address,
        operator_state_retriever_addr: Address,
        delegation_manager_addr: Address,
        avs_directory_addr: Address,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
        operator_info_service: I,
    ) -> Result<Self, AvsError> {
        let avs_registry_manager = AvsRegistryContractManager::build(
            service_manager_addr,
            registry_coordinator_addr,
            operator_state_retriever_addr,
            delegation_manager_addr,
            avs_directory_addr,
            eth_client_http,
            eth_client_ws,
            signer,
        )
        .await?;

        Ok(AvsRegistryServiceChainCaller {
            operator_info_service,
            avs_registry_manager,
        })
    }

    async fn get_operator_info(&self, operator_id: B256) -> Result<Option<OperatorInfo>, AvsError> {
        let operator_addr = self
            .avs_registry_manager
            .get_operator_from_id(operator_id)
            .await
            .map_err(|e| {
                AvsError::OperatorError(format!(
                    "Failed to get operator address from pubkey hash: {:?}",
                    e
                ))
            })?;

        self.operator_info_service
            .get_operator_info(operator_addr)
            .await
            .map_err(|e| AvsError::OperatorError(format!("Failed to get operator info from operatorInfoService (operatorAddr: {:?}, operatorId: {:?}): {}", operator_addr, operator_id, e)))
    }
}
