use async_trait::async_trait;
use dfns_cggmp21::supported_curves::Secp256k1;
use dfns_cggmp21::KeyShare;
use gadget_common::client::{AccountId, ClientWithApi, JobsClient};
use gadget_common::debug_logger::DebugLogger;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::{GadgetProtocol, JobInitMetadata, WorkManagerConfig};
use gadget_common::keystore::{ECDSAKeyStore, KeystoreBackend};
use gadget_common::protocol::AsyncProtocol;
use gadget_common::{Block, BlockImportNotification};
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use pallet_jobs_rpc_runtime_api::JobsApi;
use rand::SeedableRng;
use sc_client_api::Backend;
use sp_api::ProvideRuntimeApi;
use sp_core::keccak_256;
use std::collections::HashMap;
use std::sync::Arc;
use tangle_primitives::jobs::{
    DKGTSSSignatureResult, DigitalSignatureType, JobId, JobResult, JobType,
};
use tangle_primitives::roles::{RoleType, ThresholdSignatureRoleType};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct DfnsCGGMP21KeyRotateProtocol<B: Block, BE, KBE: KeystoreBackend, C, N> {
    client: JobsClient<B, BE, C>,
    key_store: ECDSAKeyStore<KBE>,
    network: N,
    logger: DebugLogger,
    account_id: AccountId,
}

pub async fn create_protocol<B, BE, KBE, C, N>(
    account_id: AccountId,
    client: JobsClient<B, BE, C>,
    network: N,
    logger: DebugLogger,
    key_store: ECDSAKeyStore<KBE>,
) -> DfnsCGGMP21KeyRotateProtocol<B, BE, KBE, C, N>
where
    B: Block,
    BE: Backend<B>,
    C: ClientWithApi<B, BE>,
    KBE: KeystoreBackend,
    N: Network,
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    DfnsCGGMP21KeyRotateProtocol {
        client,
        network,
        key_store,
        logger,
        account_id,
    }
}

#[async_trait]
impl<
        B: Block,
        BE: Backend<B> + 'static,
        C: ClientWithApi<B, BE>,
        KBE: KeystoreBackend,
        N: Network,
    > GadgetProtocol<B, BE, C> for DfnsCGGMP21KeyRotateProtocol<B, BE, KBE, C, N>
where
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    async fn create_next_job(
        &self,
        job: JobInitMetadata,
    ) -> Result<<Self as AsyncProtocol>::AdditionalParams, gadget_common::Error> {
        let job_id = job.job_id;

        let JobType::DKGTSSPhaseFour(p4_job) = job.job_type else {
            panic!("Should be valid type")
        };
        let phase_one_job_id = p4_job.phase_one_id;
        let new_phase_one_job_id = p4_job.new_phase_one_id;

        let phase1_job = job.phase1_job.expect("Should exist for a phase 2 job");
        let participants = phase1_job.clone().get_participants().expect("Should exist");
        let threshold = phase1_job.get_threshold().expect("Should exist") as u16;

        let i = participants
            .iter()
            .position(|p| p == &self.account_id)
            .expect("Should exist") as u16;
        // TODO: decide how we will pick the signers.
        // For now, we will just pick the first t participants.
        let signers = participants
            .iter()
            .enumerate()
            .take(threshold as usize)
            .map(|(i, _)| i as u16)
            .collect::<Vec<_>>();

        let new_key = self
            .client
            .query_job_result(
                RoleType::Tss(ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1),
                new_phase_one_job_id,
            )
            .await?;

        let key = self
            .key_store
            .get(&phase_one_job_id)
            .await
            .map_err(|err| gadget_common::Error::ClientError {
                err: err.to_string(),
            })?
            .ok_or_else(|| gadget_common::Error::ClientError {
                err: format!("No key found for job ID: {job_id:?}"),
            })?;

        if participants.contains(&self.account_id) && signers.contains(&i) {
            let user_id_to_account_id_mapping = Arc::new(
                participants
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|r| (r.0 as UserID, r.1))
                    .collect(),
            );

            let params = DfnsCGGMP21KeyRotateExtraParams {
                i,
                t: threshold,
                signers,
                job_id,
                role_type: RoleType::Tss(ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1),
                key,
                input_data_to_sign,
                user_id_to_account_id_mapping,
            };
            Ok(params)
        } else {
            Err(gadget_common::Error::ClientError {
                err: format!(
                    "Account ID {account_id:?} is not a participant or signer for job {job_id:?}",
                    account_id = self.account_id,
                    job_id = job_id
                ),
            })
        }
    }

    async fn process_block_import_notification(
        &self,
        _notification: BlockImportNotification<B>,
        _job_manager: &ProtocolWorkManager<WorkManager>,
    ) -> Result<(), gadget_common::Error> {
        Ok(())
    }

    async fn process_error(
        &self,
        error: gadget_common::Error,
        _job_manager: &ProtocolWorkManager<WorkManager>,
    ) {
        log::error!(target: "gadget", "Error: {error:?}");
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn role_filter(&self, role: RoleType) -> bool {
        matches!(
            role,
            RoleType::Tss(ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1)
        )
    }

    fn phase_filter(&self, job: JobType<AccountId>) -> bool {
        matches!(job, JobType::DKGTSSPhaseFour(_))
    }

    fn client(&self) -> &JobsClient<B, BE, C> {
        &self.client
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

pub struct DfnsCGGMP21KeyRotateExtraParams {
    i: u16,
    t: u16,
    signers: Vec<u16>,
    job_id: JobId,
    role_type: RoleType,
    key: KeyShare<Secp256k1>,
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
    > AsyncProtocol for DfnsCGGMP21KeyRotateProtocol<B, BE, KBE, C, N>
where
    <C as ProvideRuntimeApi<B>>::Api: JobsApi<B, AccountId>,
{
    type AdditionalParams = DfnsCGGMP21KeyRotateExtraParams;
    async fn generate_protocol_from(
        &self,
        associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
        associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
        associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
        associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
        protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
        additional_params: Self::AdditionalParams,
    ) -> Result<BuiltExecutableJobWrapper, JobError> {
        let debug_logger_post = self.logger.clone();
        let logger = debug_logger_post.clone();
        let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
        let protocol_output_clone = protocol_output.clone();
        let client = self.client.clone();
        let id = self.account_id;
        let network = self.network.clone();

        let (i, signers, t, key, input_data_to_sign, mapping) = (
            additional_params.i,
            additional_params.signers,
            additional_params.t,
            additional_params.key,
            additional_params.input_data_to_sign.clone(),
            additional_params.user_id_to_account_id_mapping.clone(),
        );

        let public_key_bytes = key.shared_public_key().to_bytes(true).to_vec();
        let input_data_to_sign2 = input_data_to_sign.clone();

        Ok(JobBuilder::new()
            .protocol(async move {
                let mut rng = rand::rngs::StdRng::from_entropy();
                let protocol_message_channel =
                    super::util::CloneableUnboundedReceiver::from(protocol_message_channel);

                logger.info(format!(
                    "Starting Signing Protocol with params: i={i}, t={t}"
                ));

                let job_id_bytes = additional_params.job_id.to_be_bytes();
                let mix = keccak_256(b"dnfs-cggmp21-signing");
                let eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
                let eid = dfns_cggmp21::ExecutionId::new(&eid_bytes);
                let (
                    signing_tx_to_outbound,
                    signing_rx_async_proto,
                    _broadcast_tx_to_outbound,
                    _broadcast_rx_from_gadget,
                ) = super::util::create_job_manager_to_async_protocol_channel_split::<_, (), _>(
                    protocol_message_channel.clone(),
                    associated_block_id,
                    associated_retry_id,
                    associated_session_id,
                    associated_task_id,
                    mapping.clone(),
                    id,
                    network.clone(),
                );

                let delivery = (signing_rx_async_proto, signing_tx_to_outbound);
                let party = dfns_cggmp21::round_based::MpcParty::connected(delivery);
                let data_hash = keccak_256(&input_data_to_sign);
                let data_to_sign = dfns_cggmp21::DataToSign::from_scalar(
                    dfns_cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(data_hash),
                );
                let signature = dfns_cggmp21::signing(eid, i, &signers, &key)
                    .sign(&mut rng, party, data_to_sign)
                    .await
                    .map_err(|err| JobError {
                        reason: format!("Signing protocol error: {err:?}"),
                    })?;

                // Normalize the signature
                let signature = signature.normalize_s();
                logger.debug("Finished AsyncProtocol - Signing");
                *protocol_output.lock().await = Some(signature);
                Ok(())
            })
            .post(async move {
                // Submit the protocol output to the blockchain
                if let Some(signature) = protocol_output_clone.lock().await.take() {
                    let mut signature_bytes = [0u8; 65];
                    signature.write_to_slice(&mut signature_bytes[0..64]);
                    // To figure out the recovery ID, we need to try all possible values of v
                    // in our case, v can be 0 or 1
                    let mut v = 0u8;
                    loop {
                        let mut signature_bytes = signature_bytes;
                        let data_hash = keccak_256(&input_data_to_sign2);
                        signature_bytes[64] = v;
                        let res =
                            sp_io::crypto::secp256k1_ecdsa_recover(&signature_bytes, &data_hash);
                        match res {
                            Ok(key) if key[..32] == public_key_bytes[1..] => {
                                // Found the correct v
                                break;
                            }
                            Ok(_) => {
                                // Found a key, but not the correct one
                                // Try the other v value
                                v = 1;
                                continue;
                            }
                            Err(_) if v == 1 => {
                                // We tried both v values, but no key was found
                                // This should never happen, but if it does, we will just
                                // leave v as 1 and break
                                break;
                            }
                            Err(_) => {
                                // No key was found, try the other v value
                                v = 1;
                                continue;
                            }
                        }
                    }
                    signature_bytes[64] = v + 27;

                    let job_result = JobResult::DKGPhaseTwo(DKGTSSSignatureResult {
                        signature_type: DigitalSignatureType::Ecdsa,
                        data: additional_params.input_data_to_sign,
                        signature: signature_bytes.to_vec(),
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