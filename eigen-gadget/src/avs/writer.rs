use alloy_primitives::{Bytes, U256};
use alloy_rpc_types::TransactionReceipt;
use async_trait::async_trait;
use eigen_utils::types::{AvsError, TaskIndex};
use eigen_utils::Config;

use super::IncredibleSquaringTaskManager::{Task, TaskResponse, TaskResponseMetadata};
use super::{IncredibleSquaringContractManager, IncredibleSquaringTaskManager};

#[async_trait]
pub trait IncredibleSquaringWriter: Send + Sync {
    async fn send_new_task_number_to_square(
        &self,
        num_to_square: U256,
        quorum_threshold_percentage: u8,
        quorum_numbers: Bytes,
    ) -> Result<(Task, u32), AvsError>;

    async fn raise_challenge(
        &self,
        task: Task,
        task_response: TaskResponse,
        task_response_metadata: TaskResponseMetadata,
        pubkeys_of_non_signing_operators: Vec<IncredibleSquaringTaskManager::G1Point>,
    ) -> Result<TransactionReceipt, AvsError>;

    async fn send_aggregated_response(
        &self,
        task: Task,
        task_response: TaskResponse,
        non_signer_stakes_and_signature: IncredibleSquaringTaskManager::NonSignerStakesAndSignature,
    ) -> Result<TransactionReceipt, AvsError>;
}

#[async_trait]
impl<T: Config> IncredibleSquaringWriter for IncredibleSquaringContractManager<T> {
    async fn send_new_task_number_to_square(
        &self,
        num_to_square: U256,
        quorum_threshold_percentage: u8,
        quorum_numbers: Bytes,
    ) -> Result<(Task, TaskIndex), AvsError> {
        let task_manager = IncredibleSquaringTaskManager::new(
            self.task_manager_addr,
            self.eth_client_http.clone(),
        );
        let receipt = task_manager
            .createNewTask(
                num_to_square,
                quorum_threshold_percentage as u32,
                quorum_numbers,
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<IncredibleSquaringTaskManager::NewTaskCreated>()
                    .ok()
            })
            .map(|log| (log.inner.task.clone(), log.inner.taskIndex))
            .ok_or(AvsError::InvalidLogDecodingError(
                "NewTaskCreated event not found".to_string(),
            ))
    }

    async fn raise_challenge(
        &self,
        task: Task,
        task_response: TaskResponse,
        task_response_metadata: TaskResponseMetadata,
        pubkeys_of_non_signing_operators: Vec<IncredibleSquaringTaskManager::G1Point>,
    ) -> Result<TransactionReceipt, AvsError> {
        let task_manager = IncredibleSquaringTaskManager::new(
            self.task_manager_addr,
            self.eth_client_http.clone(),
        );
        task_manager
            .raiseAndResolveChallenge(
                task,
                task_response,
                task_response_metadata,
                pubkeys_of_non_signing_operators,
            )
            .send()
            .await?
            .get_receipt()
            .await
            .map_err(AvsError::from)
    }

    async fn send_aggregated_response(
        &self,
        task: Task,
        task_response: TaskResponse,
        non_signer_stakes_and_signature: IncredibleSquaringTaskManager::NonSignerStakesAndSignature,
    ) -> Result<TransactionReceipt, AvsError> {
        let task_manager = IncredibleSquaringTaskManager::new(
            self.task_manager_addr,
            self.eth_client_http.clone(),
        );
        task_manager
            .respondToTask(task, task_response, non_signer_stakes_and_signature)
            .send()
            .await?
            .get_receipt()
            .await
            .map_err(AvsError::from)
    }
}
