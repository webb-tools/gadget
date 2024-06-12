use super::{Erc20Mock, IncredibleSquaringContractManager, IncredibleSquaringTaskManager};
use alloy_primitives::{Address, Bytes, FixedBytes};
use alloy_provider::Provider;

use async_trait::async_trait;
use eigen_utils::{types::AvsError, Config};

#[async_trait]
pub trait IncredibleSquaringReader {
    type Erc20Mock;

    async fn check_signatures(
        &self,
        msg_hash: FixedBytes<32>,
        quorum_numbers: Bytes,
        reference_block_number: u32,
        non_signer_stakes_and_signature: IncredibleSquaringTaskManager::NonSignerStakesAndSignature,
    ) -> Result<IncredibleSquaringTaskManager::QuorumStakeTotals, AvsError>;

    async fn get_erc20_mock(&self, token_addr: Address) -> Result<Self::Erc20Mock, AvsError>;
}

#[async_trait]
impl<T: Config> IncredibleSquaringReader for IncredibleSquaringContractManager<T> {
    type Erc20Mock = Erc20Mock::Erc20MockInstance<T::TH, T::PH>;

    async fn check_signatures(
        &self,
        msg_hash: FixedBytes<32>,
        quorum_numbers: Bytes,
        reference_block_number: u32,
        non_signer_stakes_and_signature: IncredibleSquaringTaskManager::NonSignerStakesAndSignature,
    ) -> Result<IncredibleSquaringTaskManager::QuorumStakeTotals, AvsError> {
        let task_manager = IncredibleSquaringTaskManager::new(
            self.task_manager_addr,
            self.eth_client_http.clone(),
        );
        let stake_totals_per_quorum = task_manager
            .checkSignatures(
                msg_hash,
                quorum_numbers,
                reference_block_number,
                non_signer_stakes_and_signature,
            )
            .call()
            .await
            .map(|x| x._0)?;
        Ok(stake_totals_per_quorum)
    }

    async fn get_erc20_mock(
        &self,
        token_addr: Address,
    ) -> Result<Erc20Mock::Erc20MockInstance<T::TH, T::PH>, AvsError> {
        let erc20_mock = Erc20Mock::new(token_addr, self.eth_client_http.clone());
        Ok(erc20_mock)
    }
}
