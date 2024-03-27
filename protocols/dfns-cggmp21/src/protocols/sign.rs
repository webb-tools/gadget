use crate::protocols::{DefaultCryptoHasher, DefaultSecurityLevel};
use dfns_cggmp21::generic_ec::coords::HasAffineX;
use dfns_cggmp21::generic_ec::{Curve, Point};
use dfns_cggmp21::round_based::{Delivery, MpcParty};
use dfns_cggmp21::security_level::SecurityLevel;
use dfns_cggmp21::signing::msg::Msg;
use dfns_cggmp21::signing::SigningBuilder;
use dfns_cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use dfns_cggmp21::{DataToSign, KeyShare};
use digest::typenum::U32;
use digest::Digest;
use gadget_common::client::ClientWithApi;
use gadget_common::config::DebugLogger;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::*;
use gadget_common::prelude::{FullProtocolConfig, Network};
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::jobs::tss::DigitalSignatureScheme;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use rand::{CryptoRng, RngCore, SeedableRng};
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use crate::protocols::util::SignatureVerifier;

use super::keygen::create_party;

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::DfnsSigningProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<DfnsCGGMP21SigningExtraParams, gadget_common::Error> {
    let job_id = job.job_id;

    let jobs::JobType::DKGTSSPhaseTwo(p2_job) = job.job_type else {
        panic!("Should be valid type")
    };
    let input_data_to_sign = p2_job.submission.0.to_vec();
    let previous_job_id = p2_job.phase_one_id;

    let phase1_job = job.phase1_job.expect("Should exist for a phase 2 job");
    let t = phase1_job.get_threshold().expect("Should exist") as u16;

    let seed = keccak_256(&[&job_id.to_be_bytes()[..], &job.retry_id.to_be_bytes()[..]].concat());
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let (i, signers, mapping) = super::util::choose_signers(
        &mut rng,
        &config.key_store.pair().public(),
        &job.participants_role_ids,
        t,
    )?;
    let key = config
        .key_store
        .get_job_result(previous_job_id)
        .await
        .map_err(|err| gadget_common::Error::ClientError {
            err: err.to_string(),
        })?
        .ok_or_else(|| gadget_common::Error::ClientError {
            err: format!("No key found for job ID: {job_id:?}"),
        })?;

    let user_id_to_account_id_mapping = Arc::new(mapping);

    let params = DfnsCGGMP21SigningExtraParams {
        i,
        t,
        signers,
        job_id,
        role_type: job.role_type,
        serialized_key_share: key,
        input_data_to_sign,
        user_id_to_account_id_mapping,
    };
    Ok(params)
}

#[derive(Clone)]
pub struct DfnsCGGMP21SigningExtraParams {
    i: u16,
    t: u16,
    signers: Vec<u16>,
    job_id: u64,
    role_type: roles::RoleType,
    serialized_key_share: Vec<u8>,
    input_data_to_sign: Vec<u8>,
    user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_and_serialize_signing<'r, E, L, R, D, H>(
    logger: &DebugLogger,
    tracer: &mut dfns_cggmp21::progress::PerfProfiler,
    eid: dfns_cggmp21::ExecutionId<'r>,
    i: u16,
    signers: Vec<u16>,
    msg: DataToSign<E>,
    key: Vec<u8>,
    party: MpcParty<Msg<E, H>, D>,
    rng: &mut R,
) -> Result<Vec<u8>, JobError>
where
    E: Curve,
    Point<E>: HasAffineX<E>,
    L: SecurityLevel,
    R: RngCore + CryptoRng,
    D: Delivery<Msg<E, H>>,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
{
    let key: KeyShare<E, L> = bincode2::deserialize(&key).map_err(|err| JobError {
        reason: format!("Signing protocol error: {err:?}"),
    })?;
    let signing_builder = SigningBuilder::<E, L, H>::new(eid, i, &signers, &key);
    let signature = signing_builder
        .set_progress_tracer(tracer)
        .sign(rng, party, msg)
        .await
        .map_err(|err| JobError {
            reason: format!("Signing protocol error: {err:?}"),
        })?;

    logger.info("Done signing");

    let perf_report = tracer.get_report().map_err(|err| JobError {
        reason: format!("Signing protocol error: {err:?}"),
    })?;
    logger.trace(format!("Signing protocol report: {perf_report}"));
    // Normalize the signature
    let signature = signature.normalize_s();
    let mut ret = [0u8; 64];
    signature.write_to_slice(&mut ret);
    Ok(ret.to_vec())
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::DfnsSigningProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: DfnsCGGMP21SigningExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let debug_logger_post = config.logger.clone();
    let logger = debug_logger_post.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let client = config.get_jobs_client();
    let my_role_id = config.key_store.pair().public();
    let network = config.clone();

    let (i, signers, t, serialized_key_share, role_type, input_data_to_sign, mapping) = (
        additional_params.i,
        additional_params.signers,
        additional_params.t,
        additional_params.serialized_key_share,
        additional_params.role_type.clone(),
        additional_params.input_data_to_sign.clone(),
        additional_params.user_id_to_account_id_mapping.clone(),
    );

    let public_key = get_public_key_from_serialized_key_share_bytes::<DefaultSecurityLevel>(
        &role_type,
        &serialized_key_share,
    )?;

    Ok(JobBuilder::new()
        .protocol(async move {
            logger.info(format!(
                "Starting Signing Protocol with params: i={i}, t={t}"
            ));

            let job_id_bytes = additional_params.job_id.to_be_bytes();
            let mix = keccak_256(b"dnfs-cggmp21-signing");
            let eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
            let eid = dfns_cggmp21::ExecutionId::new(&eid_bytes);

            let data_hash = keccak_256(&input_data_to_sign);

            let signature = match role_type {
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                ) => {
                    run_signing::<Secp256k1, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping.clone(),
                        my_role_id,
                        network.clone(),
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                    )
                    .await?
                }
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1,
                ) => {
                    run_signing::<Secp256r1, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping.clone(),
                        my_role_id,
                        network.clone(),
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                    )
                    .await?
                }
                roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
                    run_signing::<Stark, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        data_hash,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping.clone(),
                        my_role_id,
                        network.clone(),
                        &logger,
                        eid,
                        i,
                        signers,
                        serialized_key_share,
                    )
                    .await?
                }
                _ => {
                    return Err(JobError {
                        reason: format!("Invalid role type: {role_type:?}"),
                    });
                }
            };

            logger.debug("Finished AsyncProtocol - Signing");
            *protocol_output.lock().await = Some(signature);
            Ok(())
        })
        .post(async move {
            // Submit the protocol output to the blockchain
            if let Some(signature) = protocol_output_clone.lock().await.take() {
                let (signature_scheme, data_hash) = validate_dfns_signature_by_role(
                    &additional_params.role_type,
                    &signature,
                    &additional_params.input_data_to_sign,
                    &public_key,
                )?;

                let job_result = jobs::JobResult::DKGPhaseTwo(jobs::tss::DKGTSSSignatureResult {
                    signature_scheme,
                    data: BoundedVec(data_hash.to_vec()),
                    signature: BoundedVec(signature.to_vec()),
                    verifying_key: BoundedVec(public_key),
                    derivation_path: None,
                    __subxt_unused_type_params: Default::default(),
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

pub fn get_public_key_from_serialized_key_share_bytes<S: SecurityLevel>(
    role_type: &roles::RoleType,
    serialized_key_share: &[u8],
) -> Result<Vec<u8>, JobError> {
    match role_type {
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1) => {
            get_key_share::<Secp256k1, S>(serialized_key_share)
                .map(|key_share| key_share.shared_public_key().to_bytes(true).to_vec())
        }
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1) => {
            get_key_share::<Secp256r1, S>(serialized_key_share)
                .map(|key_share| key_share.shared_public_key().to_bytes(true).to_vec())
        }
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
            get_key_share::<Stark, S>(serialized_key_share)
                .map(|key_share| key_share.shared_public_key().to_bytes(true).to_vec())
        }
        _ => Err(JobError {
            reason: format!("Invalid role type: {role_type:?}"),
        }),
    }
}

pub fn get_key_share<E: Curve, S: SecurityLevel>(
    serialized_key_share: &[u8],
) -> Result<KeyShare<E, S>, JobError> {
    bincode2::deserialize::<KeyShare<E, S>>(serialized_key_share).map_err(|err| JobError {
        reason: format!("Signing protocol error: {err:?}"),
    })
}

pub fn validate_dfns_signature_by_role(
    role_type: &roles::RoleType,
    signature: &[u8],
    input_data_to_sign: &[u8],
    public_key_bytes: &[u8],
) -> Result<(DigitalSignatureScheme, [u8; 32]), JobError> {
    match role_type {
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1) => {
            let data_hash = validate_dfns_signature::<Secp256k1>(
                signature,
                input_data_to_sign,
                public_key_bytes,
            )?;
            Ok((DigitalSignatureScheme::EcdsaSecp256k1, data_hash))
        }
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1) => {
            let data_hash = validate_dfns_signature::<Secp256r1>(
                signature,
                input_data_to_sign,
                public_key_bytes,
            )?;
            Ok((DigitalSignatureScheme::EcdsaSecp256r1, data_hash))
        }
        roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
            let data_hash =
                validate_dfns_signature::<Stark>(signature, input_data_to_sign, public_key_bytes)?;
            Ok((DigitalSignatureScheme::EcdsaStark, data_hash))
        }
        _ => Err(JobError {
            reason: format!("Invalid role type: {role_type:?}"),
        }),
    }
}

fn validate_dfns_signature<E: SignatureVerifier>(
    signature: &[u8],
    input_data_to_sign: &[u8],
    public_key_bytes: &[u8],
) -> Result<[u8; 32], JobError> {
    if signature.len() != 64 {
        return Err(JobError {
            reason: format!("Invalid signature length: {}", signature.len()),
        });
    }

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..64].copy_from_slice(&signature[..64]);
    let data_hash = keccak_256(input_data_to_sign);

    E::verify_signature(signature_bytes, &data_hash, public_key_bytes)?;

    Ok(data_hash)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_signing<
    'a,
    E: Curve,
    S: SecurityLevel,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
    N: Network,
>(
    data_to_sign: [u8; 32],
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    mapping: Arc<HashMap<UserID, ecdsa::Public>>,
    my_role_id: ecdsa::Public,
    network: N,
    logger: &DebugLogger,
    eid: dfns_cggmp21::ExecutionId<'a>,
    i: u16,
    signers: Vec<u16>,
    serialized_key_share: Vec<u8>,
) -> Result<Vec<u8>, JobError>
where
    Point<E>: HasAffineX<E>,
{
    let mut tracer = dfns_cggmp21::progress::PerfProfiler::new();
    let mut rng = rand::rngs::StdRng::from_entropy();

    let data_to_sign = DataToSign::<E>::from_scalar(
        dfns_cggmp21::generic_ec::Scalar::<E>::from_be_bytes_mod_order(data_to_sign),
    );

    let (_, _, party) = create_party::<E, _, S, Msg<E, H>>(
        protocol_message_channel,
        associated_block_id,
        associated_retry_id,
        associated_session_id,
        associated_task_id,
        mapping.clone(),
        my_role_id,
        network.clone(),
        logger.clone(),
        i,
    );
    run_and_serialize_signing::<E, S, _, _, H>(
        logger,
        &mut tracer,
        eid,
        i,
        signers,
        data_to_sign,
        serialized_key_share,
        party,
        &mut rng,
    )
    .await
}
