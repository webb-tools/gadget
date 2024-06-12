pub mod reader;
pub mod subscriber;
pub mod writer;

use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types::{Log, TransactionReceipt};
use alloy_sol_types::sol;

use eigen_contracts::RegistryCoordinator;
use eigen_utils::{
    crypto::bls::{G1Point, Signature},
    types::{AvsError, OperatorId},
    Config,
};
use serde::{Deserialize, Serialize};
use IncredibleSquaringTaskManager::{Task, TaskResponse, TaskResponseMetadata};

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    IncredibleSquaringTaskManager,
    "contracts/out/IncredibleSquaringTaskManager.sol/IncredibleSquaringTaskManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    IncredibleSquaringServiceManager,
    "contracts/out/IncredibleSquaringServiceManager.sol/IncredibleSquaringServiceManager.json"
);

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    Erc20Mock,
    "contracts/out/Erc20Mock.sol/Erc20Mock.json"
);

#[derive(Debug, Clone)]
pub struct TaskResponseData {
    pub task_response: TaskResponse,
    pub task_response_metadata: TaskResponseMetadata,
    pub non_signing_operator_keys: Vec<IncredibleSquaringTaskManager::G1Point>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTaskResponse {
    pub task_response: Vec<u8>,
    pub bls_signature: Signature,
    pub operator_id: OperatorId,
}

#[derive(Debug, Clone)]
pub struct SetupConfig<T: Config> {
    pub registry_coordinator_addr: Address,
    pub operator_state_retriever_addr: Address,
    pub delegate_manager_addr: Address,
    pub avs_directory_addr: Address,
    pub eth_client_http: T::PH,
    pub eth_client_ws: T::PW,
    pub signer: T::S,
}

#[derive(Clone)]
pub struct IncredibleSquaringContractManager<T: Config> {
    pub task_manager_addr: Address,
    pub service_manager_addr: Address,
    pub eth_client_http: T::PH,
    pub eth_client_ws: T::PW,
    pub signer: T::S,
}

impl<T: Config> IncredibleSquaringContractManager<T> {
    pub async fn build(
        registry_coordinator_addr: Address,
        _operator_state_retriever_addr: Address,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        signer: T::S,
    ) -> Result<Self, AvsError> {
        let registry_coordinator = RegistryCoordinator::RegistryCoordinatorInstance::new(
            registry_coordinator_addr,
            eth_client_http.clone(),
        );
        let service_manager_addr = registry_coordinator
            .serviceManager()
            .call()
            .await
            .map(|x| x._0)?;

        let service_manager =
            IncredibleSquaringServiceManager::new(service_manager_addr, eth_client_http.clone());

        let task_manager_addr = service_manager
            .incredibleSquaringTaskManager()
            .call()
            .await
            .map(|x| x._0)?;

        Ok(Self {
            task_manager_addr,
            service_manager_addr,
            eth_client_http,
            eth_client_ws,
            signer,
        })
    }

    pub async fn create_new_task(
        &self,
        num_to_square: U256,
        quorum_threshold_percentage: u32,
        quorum_numbers: Bytes,
    ) -> Result<TransactionReceipt, AvsError> {
        let task_manager = IncredibleSquaringTaskManager::new(
            self.task_manager_addr,
            self.eth_client_http.clone(),
        );
        task_manager
            .createNewTask(num_to_square, quorum_threshold_percentage, quorum_numbers)
            .send()
            .await?
            .get_receipt()
            .await
            .map_err(AvsError::from)
    }

    pub async fn parse_new_task_created(
        &self,
        log: &Log,
    ) -> Result<Log<IncredibleSquaringTaskManager::NewTaskCreated>, AvsError> {
        log.log_decode::<IncredibleSquaringTaskManager::NewTaskCreated>()
            .map_err(AvsError::from)
    }

    pub async fn raise_and_resolve_challenge(
        &self,
        task: Task,
        task_response: TaskResponse,
        task_response_metadata: TaskResponseMetadata,
        pubkeys_of_non_signing_operators: Vec<G1Point>,
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
                pubkeys_of_non_signing_operators
                    .iter()
                    .map(|pt| IncredibleSquaringTaskManager::G1Point { X: pt.x, Y: pt.y })
                    .collect(),
            )
            .send()
            .await?
            .get_receipt()
            .await
            .map_err(AvsError::from)
    }

    pub async fn respond_to_task(
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
