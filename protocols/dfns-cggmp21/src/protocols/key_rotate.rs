use crate::protocols::{DefaultCryptoHasher, DefaultSecurityLevel};
use dfns_cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use gadget_common::client::ClientWithApi;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::FullProtocolConfig;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use rand::SeedableRng;
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use super::sign::validate_dfns_signature_by_role;

pub async fn create_next_job<C: ClientWithApi, KBE: KeystoreBackend, N: Network>(
    config: &crate::DfnsKeyRotateProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<DfnsCGGMP21KeyRotateExtraParams, Error> {
    let job_id = job.job_id;

    let jobs::JobType::DKGTSSPhaseFour(p4_job) = job.job_type else {
        panic!("Should be valid type")
    };
    let phase_one_id = p4_job.phase_one_id;
    let new_phase_one_id = p4_job.new_phase_one_id;

    let phase1_job = job.phase1_job.expect("Should exist for a phase 2 job");
    let t = phase1_job.get_threshold().expect("Should exist") as u16;

    let seed = keccak_256(&[&job_id.to_be_bytes()[..], &job.retry_id.to_be_bytes()[..]].concat());
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
    let my_id = config.key_store.pair().public();

    let (i, signers, mapping) =
        super::util::choose_signers(&mut rng, &my_id, &job.participants_role_ids, t)?;
    config.logger.info(format!(
        "We are selected to sign: i={i}, signers={signers:?} | signers len: {}",
        signers.len()
    ));
    config
        .logger
        .info(format!("Mapping for network: {mapping:?}"));

    if mapping[&(i as u32)] != my_id {
        return Err(Error::ClientError {
            err: format!("Invalid mapping for our id: {my_id:?}"),
        });
    }

    let new_key = config
        .key_store
        .get_job_result(new_phase_one_id)
        .await
        .map_err(|err| Error::ClientError {
            err: err.to_string(),
        })?
        .ok_or_else(|| Error::ClientError {
            err: format!("No new key found for job ID: {new_phase_one_id:?}"),
        })?;

    let key = config
        .key_store
        .get_job_result(phase_one_id)
        .await
        .map_err(|err| gadget_common::Error::ClientError {
            err: err.to_string(),
        })?
        .ok_or_else(|| gadget_common::Error::ClientError {
            err: format!("No key found for job ID: {job_id:?}"),
        })?;

    let user_id_to_account_id_mapping = Arc::new(mapping);

    let params = DfnsCGGMP21KeyRotateExtraParams {
        i,
        t,
        signers,
        job_id,
        phase_one_id,
        new_phase_one_id,
        role_type: job.role_type,
        key,
        new_key,
        user_id_to_account_id_mapping,
    };

    Ok(params)
}

#[derive(Clone)]
pub struct DfnsCGGMP21KeyRotateExtraParams {
    i: u16,
    t: u16,
    signers: Vec<u16>,
    job_id: u64,
    phase_one_id: u64,
    new_phase_one_id: u64,
    role_type: roles::RoleType,
    key: Vec<u8>,
    new_key: Vec<u8>,
    user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn generate_protocol_from<C: ClientWithApi, KBE: KeystoreBackend, N: Network>(
    config: &crate::DfnsKeyRotateProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: DfnsCGGMP21KeyRotateExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let debug_logger_post = config.logger.clone();
    let logger = debug_logger_post.clone();
    let logger_clone = logger.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let client = config.get_jobs_client();
    let role_id = config.key_store.pair().public();
    let phase_one_id = additional_params.phase_one_id;
    let network = config.clone();

    let (
        i,
        signers,
        t,
        new_phase_one_id,
        role_type,
        serialized_key_share,
        new_serialized_key_share,
        mapping,
    ) = (
        additional_params.i,
        additional_params.signers,
        additional_params.t,
        additional_params.new_phase_one_id,
        additional_params.role_type.clone(),
        additional_params.key,
        additional_params.new_key.clone(),
        additional_params.user_id_to_account_id_mapping.clone(),
    );

    let public_key = super::sign::get_public_key_from_serialized_key_share_bytes::<
        DefaultSecurityLevel,
    >(&role_type, &serialized_key_share)?;

    let new_public_key = super::sign::get_public_key_from_serialized_key_share_bytes::<
        DefaultSecurityLevel,
    >(&role_type, &new_serialized_key_share)?;

    // We're signing over the hash of the new public key using the old public key
    let data_hash = keccak_256(&new_public_key);
    Ok(JobBuilder::new()
        .protocol(async move {
            logger.info(format!(
                "Starting Key Rotation Protocol with params: i={i}, t={t} | JobId: {}",
                additional_params.job_id,
            ));

            let job_id_bytes = additional_params.job_id.to_be_bytes();
            let mix = keccak_256(b"dnfs-cggmp21-key-rotate");
            let eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
            let eid = dfns_cggmp21::ExecutionId::new(&eid_bytes);

            let signature = match role_type {
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                ) => {
                    super::sign::run_signing::<
                        Secp256k1,
                        DefaultSecurityLevel,
                        DefaultCryptoHasher,
                        _,
                    >(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                        None,
                    )
                    .await?
                }
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1,
                ) => {
                    super::sign::run_signing::<
                        Secp256r1,
                        DefaultSecurityLevel,
                        DefaultCryptoHasher,
                        _,
                    >(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                        None,
                    )
                    .await?
                }
                roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
                    super::sign::run_signing::<Stark, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                        None,
                    )
                    .await?
                }
                _ => {
                    return Err(JobError {
                        reason: format!("Unsupported role type: {role_type:?}"),
                    });
                }
            };

            logger.debug("Finished AsyncProtocol - Key Rotation");
            *protocol_output.lock().await = Some(signature);
            Ok(())
        })
        .post(async move {
            // Submit the protocol output to the blockchain
            if let Some(signature) = protocol_output_clone.lock().await.take() {
                validate_dfns_signature_by_role(
                    &additional_params.role_type,
                    &signature,
                    &new_public_key,
                    &public_key,
                )?;
                let job_result =
                    jobs::JobResult::DKGPhaseFour(jobs::tss::DKGTSSKeyRotationResult {
                        signature_scheme: jobs::tss::DigitalSignatureScheme::EcdsaSecp256k1,
                        derivation_path: None,
                        signature: BoundedVec(signature),
                        phase_one_id,
                        new_phase_one_id,
                        new_key: BoundedVec(new_public_key),
                        key: BoundedVec(public_key),
                        __subxt_unused_type_params: Default::default(),
                    });

                client
                    .submit_job_result(
                        additional_params.role_type.clone(),
                        additional_params.job_id,
                        job_result,
                    )
                    .await
                    .map_err(|err| JobError {
                        reason: format!("Failed to submit job result: {err:?}"),
                    })?;

                logger_clone.info(
                    format!("Successfully submitted keyrotation job result for job ID: {:?} | RoleType: {:?}",
                additional_params.job_id, additional_params.role_type
                ));
            }

            Ok(())
        })
        .build())
}
