use alloy_primitives::U256;
use alloy_provider::Provider;
use alloy_rpc_types::{Log, Transaction};
use alloy_sol_types::SolCall;
use eigen_utils::types::{AvsError, TaskIndex};
use eigen_utils::Config;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::avs::subscriber::IncredibleSquaringSubscriber;
use crate::avs::writer::IncredibleSquaringWriter;
use crate::avs::IncredibleSquaringTaskManager::{NewTaskCreated, Task, TaskResponded};
use crate::avs::{
    IncredibleSquaringContractManager, IncredibleSquaringTaskManager, SetupConfig, TaskResponseData,
};

#[derive(Clone)]
pub struct Challenger<T: Config> {
    incredible_squaring_contract_manager: IncredibleSquaringContractManager<T>,
    tasks: Arc<Mutex<HashMap<TaskIndex, Task>>>,
    task_responses: Arc<Mutex<HashMap<TaskIndex, TaskResponseData>>>,
}

impl<T: Config> Challenger<T> {
    pub async fn new(c: SetupConfig<T>) -> Result<Self, Box<dyn std::error::Error>> {
        let incredible_squaring_contract_manager = IncredibleSquaringContractManager::build(
            c.registry_coordinator_addr,
            c.operator_state_retriever_addr,
            c.eth_client_http,
            c.eth_client_ws,
            c.signer,
        )
        .await?;

        Ok(Challenger {
            incredible_squaring_contract_manager,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            task_responses: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Starting Challenger.");

        let mut new_task_sub = self
            .incredible_squaring_contract_manager
            .subscribe_to_new_tasks()
            .await?;
        log::info!("Subscribed to new tasks");

        let mut task_response_sub = self
            .incredible_squaring_contract_manager
            .subscribe_to_task_responses()
            .await?;
        log::info!("Subscribed to task responses");

        loop {
            tokio::select! {
                Ok(new_task) = new_task_sub.recv() => {
                    let new_task: Log<IncredibleSquaringTaskManager::NewTaskCreated> = new_task.log_decode().unwrap();
                    log::info!("New task created log received: {:?}", new_task);
                    let task_index = self.process_new_task_created_log(&new_task).await;

                    let task_responses = self.task_responses.lock().await;
                    if task_responses.contains_key(&task_index) {
                        if let Err(e) = self.call_challenge_module(task_index).await {
                            log::error!("Error calling challenge module: {:?}", e);
                        }
                        continue;
                    }
                }
                Ok(task_response) = task_response_sub.recv() => {
                    let task_response: Log<IncredibleSquaringTaskManager::TaskResponded> = task_response.log_decode().unwrap();
                    log::info!("Task response log received: {:?}", task_response);
                    let task_index = self.process_task_response_log(&task_response).await;

                    let tasks = self.tasks.lock().await;
                    if tasks.contains_key(&task_index) {
                        if let Err(e) = self.call_challenge_module(task_index).await {
                            log::error!("Error calling challenge module: {:?}", e);
                        }
                        continue;
                    }
                }
            }
        }
    }

    async fn process_new_task_created_log(&self, new_task: &Log<NewTaskCreated>) -> u32 {
        let mut tasks = self.tasks.lock().await;
        tasks.insert(new_task.inner.taskIndex, new_task.inner.task.clone());
        new_task.inner.taskIndex
    }

    async fn process_task_response_log(&self, task_response: &Log<TaskResponded>) -> u32 {
        let task_index = task_response.inner.taskResponse.referenceTaskIndex;
        // Get the inputs necessary for raising a challenge
        let non_signing_operator_keys = self
            .get_non_signing_operator_pub_keys(task_response)
            .await
            .unwrap_or_default();
        let task_response_data = TaskResponseData {
            task_response: task_response.inner.taskResponse.clone(),
            task_response_metadata: task_response.inner.taskResponseMetadata.clone(),
            non_signing_operator_keys,
        };

        let mut task_responses = self.task_responses.lock().await;
        task_responses.insert(task_index, task_response_data);
        task_index
    }

    async fn call_challenge_module(
        &self,
        task_index: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tasks = self.tasks.lock().await;

        if let Some(task) = tasks.get(&task_index) {
            // Get the response for the task
            let task_responses = self.task_responses.lock().await;

            if let Some(response) = task_responses.get(&task_index) {
                // Check if the response is correct
                let number_to_be_squared = task.numberToBeSquared;
                let answer_in_response = response.task_response.numberSquared;
                let true_answer = number_to_be_squared.pow(U256::from(2));

                // Checking if the answer in the response submitted by aggregator is correct
                if true_answer != answer_in_response {
                    log::info!("The number squared is not correct");
                    self.raise_challenge(task_index).await?;
                }
            }
        }

        Ok(())
    }

    async fn get_non_signing_operator_pub_keys(
        &self,
        v_log: &Log<TaskResponded>,
    ) -> Result<Vec<IncredibleSquaringTaskManager::G1Point>, AvsError> {
        log::info!("vLog.Raw is: {:?}", v_log.data());

        // Get the nonSignerStakesAndSignature
        let tx_hash = v_log.transaction_hash.unwrap_or_default();
        log::info!("txHash: {:?}", tx_hash);

        let tx: Transaction = self
            .incredible_squaring_contract_manager
            .eth_client_http
            .get_transaction_by_hash(tx_hash)
            .await?;
        let calldata = tx.input;
        log::info!("calldata: {:?}", calldata);

        let method_sig = &calldata[..4];
        log::info!("methodSig: {:?}", method_sig);

        let non_signing_operator_pub_keys =
            IncredibleSquaringTaskManager::raiseAndResolveChallengeCall::abi_decode(
                &calldata[4..],
                true,
            )
            .map(|e| e.pubkeysOfNonSigningOperators)
            .map_err(AvsError::from)?;

        Ok(non_signing_operator_pub_keys)
    }

    async fn raise_challenge(&self, task_index: u32) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Challenger raising challenge. taskIndex: {}", task_index);

        let tasks = self.tasks.lock().await;
        let task = tasks.get(&task_index).unwrap();

        let task_responses = self.task_responses.lock().await;
        let response = task_responses.get(&task_index).unwrap();

        let receipt = self
            .incredible_squaring_contract_manager
            .raise_challenge(
                task.clone(),
                response.task_response.clone(),
                response.task_response_metadata.clone(),
                response.non_signing_operator_keys.clone(),
            )
            .await?;

        log::info!(
            "Tx hash of the challenge tx: {:?}",
            receipt.transaction_hash
        );

        Ok(())
    }
}
