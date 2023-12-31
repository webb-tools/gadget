use crate::protocols::state_machine::{CurrentRoundBlame, StateMachineWrapper};
use crate::protocols::util;
use crate::protocols::util::VotingMessage;
use crate::MpEcdsaProtocolConfig;
use async_trait::async_trait;
use curv::arithmetic::Converter;
use curv::elliptic::curves::Secp256k1;
use curv::BigInt;
use gadget_common::client::{AccountId, ClientWithApi, JobsClient};
use gadget_common::debug_logger::DebugLogger;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WebbWorkManager;
use gadget_common::gadget::{Job, WebbGadgetProtocol, WorkManagerConfig};
use gadget_common::keystore::{ECDSAKeyStore, KeystoreBackend};
use gadget_common::protocol::AsyncProtocol;
use gadget_common::{Block, BlockImportNotification, FinalityNotification};
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use multi_party_ecdsa::gg_2020::party_i::verify;
use multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use multi_party_ecdsa::gg_2020::state_machine::sign::{
    CompletedOfflineStage, OfflineStage, PartialSignature, SignManual,
};
use pallet_jobs_rpc_runtime_api::JobsApi;
use parity_scale_codec::Encode;
use round_based::async_runtime::watcher::StderrWatcher;
use round_based::{Msg, StateMachine};
use sc_client_api::Backend;
use sp_api::ProvideRuntimeApi;
use sp_core::ecdsa::Signature;
use sp_core::keccak_256;
use std::collections::HashMap;
use std::sync::Arc;
use tangle_primitives::jobs::{
    DKGTSSSignatureResult, DigitalSignatureType, JobId, JobResult, JobType,
};
use tangle_primitives::roles::{RoleType, ThresholdSignatureRoleType};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock;

pub struct MpEcdsaSigningProtocol<B: Block, BE, KBE: KeystoreBackend, C, N> {
    client: JobsClient<B, BE, C>,
    key_store: ECDSAKeyStore<KBE>,
    network: N,
    round_blames: Arc<
        RwLock<
            HashMap<
                <WebbWorkManager as WorkManagerInterface>::TaskID,
                tokio::sync::watch::Receiver<CurrentRoundBlame>,
            >,
        >,
    >,
    logger: DebugLogger,
    account_id: AccountId,
}

pub async fn create_protocol<B, BE, KBE, C, N>(
    config: &MpEcdsaProtocolConfig,
    logger: DebugLogger,
    client: JobsClient<B, BE, C>,
    network: N,
    key_store: ECDSAKeyStore<KBE>,
) -> MpEcdsaSigningProtocol<B, BE, KBE, C, N>
where
    B: Block,
    BE: Backend<B>,
    C: ClientWithApi<B, BE>,
    KBE: KeystoreBackend,
    N: Network,
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    MpEcdsaSigningProtocol {
        client,
        network,
        key_store,
        round_blames: Arc::new(Default::default()),
        logger,
        account_id: config.account_id,
    }
}

#[async_trait]
impl<
        B: Block,
        BE: Backend<B> + 'static,
        C: ClientWithApi<B, BE>,
        KBE: KeystoreBackend,
        N: Network,
    > WebbGadgetProtocol<B> for MpEcdsaSigningProtocol<B, BE, KBE, C, N>
where
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    async fn get_next_jobs(
        &self,
        notification: &FinalityNotification<B>,
        now: u64,
        job_manager: &ProtocolWorkManager<WebbWorkManager>,
    ) -> Result<Option<Vec<Job>>, gadget_common::Error> {
        let jobs = self
            .client
            .query_jobs_by_validator(notification.hash, self.account_id)
            .await?;

        let mut ret = vec![];

        for job in jobs {
            let job_id = job.job_id;
            let participants = job.participants.clone();
            let role_type = job.job_type.get_role_type();

            if let JobType::DKGTSSPhaseTwo(p2_job) = job.job_type {
                if p2_job.role_type != ThresholdSignatureRoleType::TssGG20 {
                    continue;
                }
                let input_data_to_sign = p2_job.submission;
                let previous_job_id = p2_job.phase_one_id;

                let participants = participants.expect("Should exist for stage 2 signing");
                let threshold = job.threshold.expect("T should exist for stage 2 signing") as u16;

                if participants.contains(&self.account_id) {
                    let task_id = job_id.to_be_bytes();
                    let task_id = keccak_256(&task_id);
                    let session_id = 0; // We are not interested in sessions for the ECDSA protocol
                                        // For the retry ID, get the latest retry and increment by 1 to set the next retry ID
                                        // If no retry ID exists, it means the job is new, thus, set the retry_id to 0
                    let retry_id = job_manager
                        .latest_retry_id(&task_id)
                        .map(|r| r + 1)
                        .unwrap_or(0);

                    if let Some(key) =
                        self.key_store.get(&previous_job_id).await.map_err(|err| {
                            gadget_common::Error::ClientError {
                                err: err.to_string(),
                            }
                        })?
                    {
                        let user_id_to_account_id_mapping = Arc::new(
                            participants
                                .clone()
                                .into_iter()
                                .enumerate()
                                .map(|r| ((r.0 + 1) as UserID, r.1))
                                .collect(),
                        );

                        let additional_params = MpEcdsaSigningExtraParams {
                            i: participants
                                .iter()
                                .position(|p| p == &self.account_id)
                                .expect("Should exist") as u16
                                + 1,
                            t: threshold,
                            signers: (0..participants.len()).map(|r| (r + 1) as u16).collect(),
                            job_id,
                            role_type,
                            key,
                            input_data_to_sign,
                            user_id_to_account_id_mapping,
                        };

                        let job = self
                            .create(session_id, now, retry_id, task_id, additional_params)
                            .await?;

                        ret.push(job);
                    } else {
                        self.logger.warn(format!(
                            "No key found for job ID: {job_id:?}",
                            job_id = job.job_id
                        ));
                    }
                }
            }
        }

        Ok(Some(ret))
    }

    async fn process_block_import_notification(
        &self,
        _notification: BlockImportNotification<B>,
        _job_manager: &ProtocolWorkManager<WebbWorkManager>,
    ) -> Result<(), gadget_common::Error> {
        Ok(())
    }

    async fn process_error(
        &self,
        error: gadget_common::Error,
        _job_manager: &ProtocolWorkManager<WebbWorkManager>,
    ) {
        log::error!(target: "mp-ecdsa", "Error: {error:?}");
    }

    fn logger(&self) -> &DebugLogger {
        &self.logger
    }

    fn get_work_manager_config(&self) -> WorkManagerConfig {
        WorkManagerConfig {
            interval: Some(crate::constants::signing_worker::JOB_POLL_INTERVAL),
            max_active_tasks: crate::constants::signing_worker::MAX_RUNNING_TASKS,
            max_pending_tasks: crate::constants::signing_worker::MAX_ENQUEUED_TASKS,
        }
    }
}

pub struct MpEcdsaSigningExtraParams {
    i: u16,
    t: u16,
    signers: Vec<u16>,
    job_id: JobId,
    role_type: RoleType,
    key: LocalKey<Secp256k1>,
    input_data_to_sign: Vec<u8>,
    user_id_to_account_id_mapping: Arc<HashMap<UserID, AccountId>>,
}

#[async_trait]
impl<
        B: Block,
        BE: Backend<B> + 'static,
        KBE: KeystoreBackend,
        C: ClientWithApi<B, BE>,
        N: Network,
    > AsyncProtocol for MpEcdsaSigningProtocol<B, BE, KBE, C, N>
where
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    type AdditionalParams = MpEcdsaSigningExtraParams;
    async fn generate_protocol_from(
        &self,
        associated_block_id: <WebbWorkManager as WorkManagerInterface>::Clock,
        associated_retry_id: <WebbWorkManager as WorkManagerInterface>::RetryID,
        associated_session_id: <WebbWorkManager as WorkManagerInterface>::SessionID,
        associated_task_id: <WebbWorkManager as WorkManagerInterface>::TaskID,
        protocol_message_rx: UnboundedReceiver<GadgetProtocolMessage>,
        additional_params: Self::AdditionalParams,
    ) -> Result<BuiltExecutableJobWrapper, JobError> {
        let blame = self.round_blames.clone();
        let debug_logger_post = self.logger.clone();
        let debug_logger_proto = debug_logger_post.clone();
        let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
        let protocol_output_clone = protocol_output.clone();
        let client = self.client.clone();
        let round_blames = self.round_blames.clone();
        let network = self.network.clone();

        let (i, signers, t, key, input_data_to_sign, mapping) = (
            additional_params.i,
            additional_params.signers,
            additional_params.t,
            additional_params.key,
            additional_params.input_data_to_sign.clone(),
            additional_params.user_id_to_account_id_mapping.clone(),
        );

        let public_key_bytes = key.public_key().to_bytes(true).to_vec();

        Ok(JobBuilder::new()
            .protocol(async move {
                let signing = OfflineStage::new(i, signers, key).map_err(|err| JobError {
                    reason: format!("Failed to create offline stage: {err:?}"),
                })?;
                let (current_round_blame_tx, current_round_blame_rx) =
                    tokio::sync::watch::channel(CurrentRoundBlame::default());

                round_blames
                    .write()
                    .await
                    .insert(associated_task_id, current_round_blame_rx);

                let (
                    tx_to_outbound_offline,
                    rx_async_proto_offline,
                    tx_to_outbound_voting,
                    rx_async_proto_voting,
                ) = util::create_job_manager_to_async_protocol_channel_split::<
                    _,
                    Msg<<OfflineStage as StateMachine>::MessageBody>,
                    VotingMessage,
                >(
                    protocol_message_rx,
                    associated_block_id,
                    associated_retry_id,
                    associated_session_id,
                    associated_task_id,
                    mapping,
                    network,
                );

                let state_machine_wrapper = StateMachineWrapper::new(
                    signing,
                    current_round_blame_tx,
                    debug_logger_proto.clone(),
                );
                let completed_offline_stage = round_based::AsyncProtocol::new(
                    state_machine_wrapper,
                    rx_async_proto_offline,
                    tx_to_outbound_offline,
                )
                .set_watcher(StderrWatcher)
                .run()
                .await
                .map_err(|err| JobError {
                    reason: format!("Keygen protocol error: {err:?}"),
                })?;

                debug_logger_proto.info(format!(
                    "*** Completed offline stage: {:?}",
                    completed_offline_stage.public_key()
                ));

                // We will sign over the unique task ID
                let message = BigInt::from_bytes(&input_data_to_sign);

                // Conclude with the voting stage
                let signature = voting_stage(
                    i,
                    t,
                    message,
                    completed_offline_stage,
                    rx_async_proto_voting,
                    tx_to_outbound_voting,
                    &debug_logger_proto,
                )
                .await?;
                *protocol_output.lock().await = Some(signature);
                Ok(())
            })
            .post(async move {
                // Check to see if there is any blame at the end of the protocol
                if let Some(blame) = blame.write().await.remove(&associated_task_id) {
                    // TODO: consider that this blame is offset by +1
                    let blame = blame.borrow();
                    if !blame.blamed_parties.is_empty() {
                        debug_logger_post.error(format!("Blame: {blame:?}"));
                        return Err(JobError {
                            reason: format!("Signing blame: {blame:?}"),
                        });
                    }
                }

                // Submit the protocol output to the blockchain
                if let Some(signature) = protocol_output_clone.lock().await.take() {
                    let signature: Vec<u8> = signature.encode();

                    let job_result = JobResult::DKGPhaseTwo(DKGTSSSignatureResult {
                        signature_type: DigitalSignatureType::Ecdsa,
                        data: additional_params.input_data_to_sign,
                        signature,
                        signing_key: public_key_bytes,
                    });

                    client
                        .submit_job_result(
                            additional_params.role_type,
                            additional_params.job_id,
                            job_result,
                        )
                        .await
                        .map_err(|err| JobError {
                            reason: format!("Failed to submit job result: {err:?}"),
                        })?;
                }

                Ok(())
            })
            .build())
    }
}

async fn voting_stage(
    offline_i: u16,
    threshold: u16,
    message: BigInt,
    completed_offline_stage: CompletedOfflineStage,
    mut msg_rx: UnboundedReceiver<VotingMessage>,
    msg_tx: UnboundedSender<VotingMessage>,
    debug_logger: &DebugLogger,
) -> Result<Signature, JobError> {
    let offline_stage_pub_key = completed_offline_stage.public_key().clone();
    let (signing, partial_signature) = SignManual::new(message.clone(), completed_offline_stage)
        .map_err(|err| JobError {
            reason: format!("Failed to create voting stage: {err:?}"),
        })?;

    let partial_sig_bytes = bincode2::serialize(&partial_signature).map_err(|err| JobError {
        reason: format!("Failed to serialize partial signature: {err:?}"),
    })?;

    let payload = VotingMessage {
        from: offline_i as UserID,
        to: None, // Broadcast to everyone
        payload: partial_sig_bytes,
    };

    msg_tx.send(payload).map_err(|err| JobError {
        reason: format!("Failed to send partial signature: {err:?}"),
    })?;

    let mut sigs = HashMap::with_capacity(threshold as _);

    while let Some(vote_message) = msg_rx.recv().await {
        let vote_message: VotingMessage = vote_message;
        if sigs.contains_key(&vote_message.from) {
            debug_logger.warn(format!(
                "Received duplicate signature from {}",
                vote_message.from
            ));
            continue;
        }

        if let Ok(p_sig) = bincode2::deserialize::<PartialSignature>(&vote_message.payload) {
            sigs.insert(vote_message.from, p_sig);

            if sigs.len() == threshold as usize {
                break;
            }
        } else {
            debug_logger.warn(format!(
                "Received invalid signature bytes from {}",
                vote_message.from
            ));
        }
    }

    if sigs.len() != threshold as usize {
        return Err(JobError {
            reason: format!(
                "Failed to collect enough signatures: {}/{}",
                sigs.len(),
                threshold
            ),
        });
    }

    // Aggregate and complete the signature
    let sigs: Vec<PartialSignature> = sigs.into_values().collect();
    let signature = signing.complete(&sigs).map_err(|err| JobError {
        reason: format!("Failed to complete signature: {err:?}"),
    })?;

    // Verify the signature
    verify(&signature, &offline_stage_pub_key, &message).map_err(|err| JobError {
        reason: format!("Failed to verify signature: {err:?}"),
    })?;

    // Convert the signature to a substrate-compatible format
    crate::util::convert_signature(debug_logger, &signature).ok_or_else(|| JobError {
        reason: "Failed to convert signature to Substrate-compatible format".to_string(),
    })
}
