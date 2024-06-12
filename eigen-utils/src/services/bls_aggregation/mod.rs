use crate::crypto::bls::{G1Point, G2Point, Signature};
use crate::services::avs_registry::AvsRegistryServiceTrait;
use crate::types::{
    bytes_to_quorum_ids, OperatorAvsState, OperatorId, QuorumNum, QuorumThresholdPercentage,
    TaskIndex, TaskResponse, TaskResponseDigest,
};
use crate::Config;
use alloy_primitives::{keccak256, Bytes, U256};
use async_trait::async_trait;

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::avs_registry::AvsRegistryServiceChainCaller;
use super::operator_info::OperatorInfoServiceTrait;

#[derive(Debug, Clone, Error)]
pub enum BlsAggregationError {
    TaskInitializationError(String, TaskIndex),
    ProcessNewSignature(String, TaskIndex),
    TaskExpiredError(TaskIndex),
    OperatorNotPartOfTaskQuorumError(OperatorId, TaskIndex),
    HashFunctionError(String),
    IncorrectSignatureError,
}

impl Display for BlsAggregationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            BlsAggregationError::TaskInitializationError(e, task_index) => {
                write!(
                    f,
                    "Task initialization error: {} for task index: {}",
                    e, task_index
                )
            }
            BlsAggregationError::TaskExpiredError(task_index) => {
                write!(f, "Task expired for task index: {}", task_index)
            }
            BlsAggregationError::OperatorNotPartOfTaskQuorumError(operator_id, task_index) => {
                write!(
                    f,
                    "Operator with id: {} not part of task quorum for task index: {}",
                    operator_id, task_index
                )
            }
            BlsAggregationError::HashFunctionError(e) => {
                write!(f, "Hash function error: {}", e)
            }
            BlsAggregationError::IncorrectSignatureError => {
                write!(f, "Incorrect signature")
            }
            BlsAggregationError::ProcessNewSignature(e, task_index) => {
                write!(
                    f,
                    "Process new signature error: {} for task index: {}",
                    e, task_index
                )
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct BlsAggregationServiceResponse {
    pub err: Option<BlsAggregationError>,
    pub task_index: TaskIndex,
    pub task_response: TaskResponse,
    pub task_response_digest: TaskResponseDigest,
    pub non_signers_pubkeys_g1: Vec<G1Point>,
    pub quorum_apks_g1: Vec<G1Point>,
    pub signers_apk_g2: G2Point,
    pub signers_agg_sig_g1: Signature,
    pub non_signer_quorum_bitmap_indices: Vec<u32>,
    pub quorum_apk_indices: Vec<u32>,
    pub total_stake_indices: Vec<u32>,
    pub non_signer_stake_indices: Vec<Vec<u32>>,
}

#[derive(Debug, Clone, Default)]
struct AggregatedOperators {
    signers_apk_g2: G2Point,
    signers_agg_sig_g1: Signature,
    signers_total_stake_per_quorum: HashMap<QuorumNum, U256>,
    signers_operator_ids_set: HashSet<OperatorId>,
}

#[async_trait]
pub trait BlsAggregationService {
    async fn initialize_new_task(
        &self,
        task_index: TaskIndex,
        task_created_block: u32,
        quorum_numbers: Bytes,
        quorum_threshold_percentages: Vec<QuorumThresholdPercentage>,
        time_to_expiry: Duration,
    ) -> Result<(), BlsAggregationError>;

    async fn process_new_signature(
        &self,
        task_index: TaskIndex,
        task_response: TaskResponse,
        bls_signature: Signature,
        operator_id: OperatorId,
    ) -> Result<(), BlsAggregationError>;
}

#[derive(Clone)]
pub struct BlsAggregatorService<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    pub aggregated_responses_tx: broadcast::Sender<BlsAggregationServiceResponse>,
    pub signed_task_resps_txs:
        Arc<Mutex<HashMap<TaskIndex, mpsc::Sender<SignedTaskResponseDigest>>>>,
    pub avs_registry_service: AvsRegistryServiceChainCaller<T, I>,
}

#[derive(Debug)]
pub struct SignedTaskResponseDigest {
    pub task_response: TaskResponse,
    pub bls_signature: Signature,
    pub operator_id: OperatorId,
    pub signature_verification_error_tx: oneshot::Sender<Result<(), BlsAggregationError>>,
}

#[async_trait]
impl<T, I> BlsAggregationService for BlsAggregatorService<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    async fn initialize_new_task(
        &self,
        task_index: TaskIndex,
        task_created_block: u32,
        quorum_numbers: Bytes,
        quorum_threshold_percentages: Vec<QuorumThresholdPercentage>,
        time_to_expiry: Duration,
    ) -> Result<(), BlsAggregationError> {
        log::debug!("AggregatorService initializing new task: {:?}", task_index);

        let (tx, rx) = mpsc::channel(100);
        self.signed_task_resps_txs
            .lock()
            .unwrap()
            .insert(task_index, tx);

        let avs_registry_service = self.avs_registry_service.clone();
        let aggregated_responses_tx = self.aggregated_responses_tx.clone();
        let signed_task_resps_txs = Arc::clone(&self.signed_task_resps_txs);

        tokio::spawn(async move {
            let service_clone = BlsAggregatorService {
                avs_registry_service,
                aggregated_responses_tx,
                signed_task_resps_txs,
            };
            service_clone
                .single_task_aggregator(
                    task_index,
                    task_created_block,
                    quorum_numbers,
                    quorum_threshold_percentages,
                    time_to_expiry,
                    rx,
                )
                .await;
        });

        Ok(())
    }

    async fn process_new_signature(
        &self,
        task_index: TaskIndex,
        task_response: TaskResponse,
        bls_signature: Signature,
        operator_id: OperatorId,
    ) -> Result<(), BlsAggregationError> {
        let tx_opt = {
            let task_resps_txs = self.signed_task_resps_txs.lock().unwrap();
            task_resps_txs.get(&task_index).cloned()
        };

        if let Some(tx) = tx_opt {
            let (tx_res, rx_res) = oneshot::channel();
            let send_result = tx
                .send(SignedTaskResponseDigest {
                    task_response,
                    bls_signature,
                    operator_id,
                    signature_verification_error_tx: tx_res,
                })
                .await;

            send_result.map_err(|_| {
                BlsAggregationError::ProcessNewSignature(
                    "Failed to send signed task response digest".to_string(),
                    task_index,
                )
            })?;

            rx_res.await.map_err(|_| {
                BlsAggregationError::ProcessNewSignature(
                    "Failed to receive signature verification result".to_string(),
                    task_index,
                )
            })?
        } else {
            Err(BlsAggregationError::TaskInitializationError(
                "Task not initialized".to_string(),
                task_index,
            ))
        }
    }
}

impl<T, I> BlsAggregatorService<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    pub fn new(
        aggregated_responses_tx: broadcast::Sender<BlsAggregationServiceResponse>,
        avs_registry_service: AvsRegistryServiceChainCaller<T, I>,
    ) -> Self {
        Self {
            aggregated_responses_tx,
            signed_task_resps_txs: Arc::new(Mutex::new(HashMap::new())),
            avs_registry_service,
        }
    }

    async fn single_task_aggregator(
        self,
        task_index: TaskIndex,
        task_created_block: u32,
        quorum_numbers: Bytes,
        quorum_threshold_percentages: Vec<QuorumThresholdPercentage>,
        time_to_expiry: Duration,
        mut rx: mpsc::Receiver<SignedTaskResponseDigest>,
    ) {
        let quorum_numbers_vec: Vec<QuorumNum> = bytes_to_quorum_ids(&quorum_numbers);
        let quorum_threshold_percentages_map: HashMap<QuorumNum, QuorumThresholdPercentage> =
            quorum_numbers_vec
                .iter()
                .cloned()
                .zip(quorum_threshold_percentages.iter().cloned())
                .collect();

        let operators_avs_state_dict = match self
            .avs_registry_service
            .get_operators_avs_state_at_block(quorum_numbers.clone(), task_created_block.into())
            .await
        {
            Ok(state) => state,
            Err(e) => {
                self.aggregated_responses_tx
                    .send(BlsAggregationServiceResponse {
                        err: Some(BlsAggregationError::TaskInitializationError(
                            e.to_string(),
                            task_index,
                        )),
                        task_index,
                        ..Default::default()
                    })
                    .unwrap();
                return;
            }
        };

        let quorums_avs_stake_dict = match self
            .avs_registry_service
            .get_quorums_avs_state_at_block(quorum_numbers.clone(), task_created_block.into())
            .await
        {
            Ok(state) => state,
            Err(e) => {
                self.aggregated_responses_tx
                    .send(BlsAggregationServiceResponse {
                        err: Some(BlsAggregationError::TaskInitializationError(
                            e.to_string(),
                            task_index,
                        )),
                        task_index,
                        ..Default::default()
                    })
                    .unwrap();
                return;
            }
        };

        let total_stake_per_quorum: HashMap<QuorumNum, U256> = quorums_avs_stake_dict
            .iter()
            .map(|(quorum_num, state)| (quorum_num.clone(), state.total_stake))
            .collect();

        let quorum_apks_g1: Vec<G1Point> = quorums_avs_stake_dict
            .values()
            .map(|state| state.agg_pubkey_g1.clone())
            .collect();

        let mut aggregated_operators_dict: HashMap<TaskResponseDigest, AggregatedOperators> =
            HashMap::new();

        let task_expired_timer = tokio::time::sleep(time_to_expiry);

        tokio::pin!(task_expired_timer);

        loop {
            tokio::select! {
                Some(signed_task_response_digest) = rx.recv() => {
                    log::debug!("Task received new signed task response digest: {:?}", signed_task_response_digest);

                    let verification_result = self.verify_signature(task_index, &signed_task_response_digest, &operators_avs_state_dict).await;

                    match verification_result {
                        Ok(task_response_digest) => {
                            let digest_aggregated_operators = aggregated_operators_dict.entry(task_response_digest)
                                .or_default();

                            let operator_avs_state = &operators_avs_state_dict[&signed_task_response_digest.operator_id];

                            digest_aggregated_operators.signers_apk_g2.add(&G2Point::from_ark_g2(&operator_avs_state.operator_info.pubkeys.g2_pubkey));
                            digest_aggregated_operators.signers_agg_sig_g1.add(&signed_task_response_digest.bls_signature);
                            digest_aggregated_operators.signers_operator_ids_set.insert(signed_task_response_digest.operator_id);

                            for (quorum_num, stake) in &operator_avs_state.stake_per_quorum {
                                *digest_aggregated_operators.signers_total_stake_per_quorum.entry(quorum_num.clone()).or_default() += stake;
                            }

                            if self.check_if_stake_thresholds_met(&digest_aggregated_operators.signers_total_stake_per_quorum, &total_stake_per_quorum, &quorum_threshold_percentages_map) {
                                let non_signers_operator_ids: Vec<OperatorId> = operators_avs_state_dict.keys()
                                    .filter(|&operator_id| !digest_aggregated_operators.signers_operator_ids_set.contains(operator_id))
                                    .cloned()
                                    .collect();

                                let non_signers_g1_pubkeys: Vec<G1Point> = non_signers_operator_ids.iter()
                                    .map(|operator_id| G1Point::from_ark_g1(&operators_avs_state_dict[operator_id].operator_info.pubkeys.g1_pubkey))
                                    .collect();

                                let indices = match self.avs_registry_service.get_check_signatures_indices(task_created_block.into(), quorum_numbers.clone(), non_signers_operator_ids.clone()).await {
                                    Ok(indices) => indices,
                                    Err(e) => {
                                        self.aggregated_responses_tx.send(BlsAggregationServiceResponse {
                                            err: Some(BlsAggregationError::TaskInitializationError(format!("Failed to get check signatures indices: {}", e), task_index)),
                                            task_index,
                                            ..Default::default()
                                        }).unwrap();
                                        return;
                                    }
                                };

                                self.aggregated_responses_tx.send(BlsAggregationServiceResponse {
                                    err: None,
                                    task_index,
                                    task_response: signed_task_response_digest.task_response,
                                    task_response_digest,
                                    non_signers_pubkeys_g1: non_signers_g1_pubkeys,
                                    quorum_apks_g1: quorum_apks_g1.clone(),
                                    signers_apk_g2: digest_aggregated_operators.signers_apk_g2.clone(),
                                    signers_agg_sig_g1: digest_aggregated_operators.signers_agg_sig_g1.clone(),
                                    non_signer_quorum_bitmap_indices: indices.nonSignerQuorumBitmapIndices,
                                    quorum_apk_indices: indices.quorumApkIndices,
                                    total_stake_indices: indices.totalStakeIndices,
                                    non_signer_stake_indices: indices.nonSignerStakeIndices,
                                }).unwrap();

                                return;
                            }
                        }
                        Err(err) => {
                            signed_task_response_digest.signature_verification_error_tx.send(Err(err)).unwrap();
                        }
                    }
                }
                _ = &mut task_expired_timer => {
                    self.aggregated_responses_tx.send(BlsAggregationServiceResponse {
                        err: Some(BlsAggregationError::TaskExpiredError(task_index)),
                        task_index,
                        ..Default::default()
                    }).unwrap();
                    return;
                }
            }
        }
    }

    async fn verify_signature(
        &self,
        task_index: TaskIndex,
        signed_task_response_digest: &SignedTaskResponseDigest,
        operators_avs_state_dict: &HashMap<OperatorId, OperatorAvsState>,
    ) -> Result<TaskResponseDigest, BlsAggregationError> {
        let operator_avs_state = operators_avs_state_dict
            .get(&signed_task_response_digest.operator_id)
            .ok_or({
                BlsAggregationError::OperatorNotPartOfTaskQuorumError(
                    signed_task_response_digest.operator_id,
                    task_index,
                )
            })?;

        let task_response_digest = keccak256(&signed_task_response_digest.task_response);

        let operator_g2_pubkey = &operator_avs_state.operator_info.pubkeys.g2_pubkey;

        let signature_verified = signed_task_response_digest
            .bls_signature
            .verify(
                &G2Point::from_ark_g2(operator_g2_pubkey),
                &task_response_digest,
            )
            .map_err(|_| BlsAggregationError::IncorrectSignatureError)?;

        if signature_verified {
            Ok(task_response_digest)
        } else {
            Err(BlsAggregationError::IncorrectSignatureError)
        }
    }

    fn check_if_stake_thresholds_met(
        &self,
        signed_stake_per_quorum: &HashMap<QuorumNum, U256>,
        total_stake_per_quorum: &HashMap<QuorumNum, U256>,
        quorum_threshold_percentages_map: &HashMap<QuorumNum, QuorumThresholdPercentage>,
    ) -> bool {
        for (quorum_num, quorum_threshold_percentage) in quorum_threshold_percentages_map {
            let signed_stake_by_quorum = signed_stake_per_quorum
                .get(quorum_num)
                .unwrap_or(&U256::ZERO);
            let total_stake_by_quorum = total_stake_per_quorum
                .get(quorum_num)
                .unwrap_or(&U256::ZERO);

            let signed_stake = signed_stake_by_quorum.saturating_mul(U256::from(100));
            let threshold_stake = total_stake_by_quorum * U256::from(quorum_threshold_percentage.0);

            if signed_stake < threshold_stake {
                return false;
            }
        }
        true
    }
}
