use crate::protocols::{DefaultCryptoHasher, DefaultSecurityLevel};
use dfns_cggmp21::generic_ec::Curve;
use dfns_cggmp21::key_refresh::msg::aux_only;
use dfns_cggmp21::key_refresh::AuxInfoGenerationBuilder;
use dfns_cggmp21::key_share::DirtyKeyShare;
use dfns_cggmp21::key_share::Validate;
use dfns_cggmp21::security_level::SecurityLevel;
use dfns_cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use dfns_cggmp21::{KeyShare, PregeneratedPrimes};
use digest::typenum::U32;
use digest::Digest;
use gadget_common::client::ClientWithApi;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::*;
use gadget_common::prelude::{DebugLogger, FullProtocolConfig};
use gadget_common::tangle_runtime::*;
use gadget_common::utils::serialize;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use rand::SeedableRng;
use round_based_21::{Incoming, Outgoing};
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

pub(crate) async fn create_next_job<C: ClientWithApi, KBE: KeystoreBackend, N: Network>(
    config: &crate::DfnsKeyRefreshProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<DfnsCGGMP21KeyRefreshExtraParams, gadget_common::Error> {
    let job_id = job.job_id;
    let role_type = job.job_type.get_role_type();

    // We can safely make this assumption because we are only creating jobs for phase one
    let jobs::JobType::DKGTSSPhaseThree(p3_job) = job.job_type else {
        panic!("Should be valid type")
    };

    let user_id_to_account_id_mapping = Arc::new(
        job.participants_role_ids
            .clone()
            .into_iter()
            .enumerate()
            .map(|r| (r.0 as UserID, r.1))
            .collect(),
    );

    let key = config
        .key_store
        .get_job_result(p3_job.phase_one_id)
        .await
        .map_err(|err| gadget_common::Error::ClientError {
            err: err.to_string(),
        })?
        .ok_or_else(|| gadget_common::Error::ClientError {
            err: format!("No key found for job ID: {job_id:?}"),
        })?;

    let phase_one_id_bytes = p3_job.phase_one_id.to_be_bytes();
    let pregenerated_primes_key =
        keccak_256(&[&b"dfns-cggmp21-keygen-primes"[..], &phase_one_id_bytes[..]].concat());
    let pregenerated_primes = config
        .key_store
        .get(&pregenerated_primes_key)
        .await?
        .ok_or_else(|| gadget_common::Error::ClientError {
            err: format!(
                "No pregenerated primes found for job ID: {}",
                p3_job.phase_one_id
            ),
        })?;

    let params = DfnsCGGMP21KeyRefreshExtraParams {
        phase_one_id: p3_job.phase_one_id,
        key,
        pregenerated_primes,
        role_type,
        job_id,
        user_id_to_account_id_mapping,
    };

    Ok(params)
}

#[derive(Clone)]
pub struct DfnsCGGMP21KeyRefreshExtraParams {
    job_id: u64,
    phase_one_id: u64,
    role_type: roles::RoleType,
    key: Vec<u8>,
    pregenerated_primes: dfns_cggmp21::PregeneratedPrimes,
    user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn generate_protocol_from<C: ClientWithApi, KBE: KeystoreBackend, N: Network>(
    config: &crate::DfnsKeyRefreshProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: DfnsCGGMP21KeyRefreshExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let key_store = config.key_store.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let client = config.get_jobs_client();
    let role_id = config.key_store.pair().public();
    let logger = config.logger.clone();
    let network = config.clone();
    let role_type = additional_params.role_type.clone();

    let (mapping, serialized_key_share, pregenerated_primes) = (
        additional_params.user_id_to_account_id_mapping,
        additional_params.key,
        additional_params.pregenerated_primes,
    );

    Ok(JobBuilder::new()
        .protocol(async move {
            let key = match role_type {
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                ) => {
                    handle_key_refresh::<Secp256k1, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        &serialized_key_share,
                        &logger,
                        additional_params.job_id,
                        pregenerated_primes,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                    )
                    .await?
                }

                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1,
                ) => {
                    handle_key_refresh::<Secp256r1, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        &serialized_key_share,
                        &logger,
                        additional_params.job_id,
                        pregenerated_primes,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                    )
                    .await?
                }

                roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
                    handle_key_refresh::<Stark, DefaultSecurityLevel, DefaultCryptoHasher, _>(
                        &serialized_key_share,
                        &logger,
                        additional_params.job_id,
                        pregenerated_primes,
                        protocol_message_channel,
                        associated_block_id,
                        associated_retry_id,
                        associated_session_id,
                        associated_task_id,
                        mapping,
                        role_id,
                        network,
                    )
                    .await?
                }
                _ => {
                    return Err(JobError {
                        reason: format!(
                            "Role type {role_type:?} is not supported for KeyRefresh protocol"
                        ),
                    })
                }
            };

            let job_result = jobs::JobResult::DKGPhaseThree(jobs::tss::DKGTSSKeyRefreshResult {
                signature_scheme: jobs::tss::DigitalSignatureScheme::EcdsaSecp256k1,
            });

            *protocol_output.lock().await = Some((key, job_result));
            Ok(())
        })
        .post(async move {
            // TODO: handle protocol blames
            if let Some((local_key, job_result)) = protocol_output_clone.lock().await.take() {
                // Update the local key share, of the phase one.
                key_store
                    .set_job_result(additional_params.phase_one_id, local_key)
                    .await
                    .map_err(|err| JobError {
                        reason: format!("Failed to store key: {err:?}"),
                    })?;

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

#[allow(clippy::too_many_arguments)]
async fn handle_key_refresh<
    E: Curve,
    S: SecurityLevel,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
    N: Network,
>(
    serialized_key_share: &[u8],
    logger: &DebugLogger,
    job_id: u64,
    pregenerated_primes: PregeneratedPrimes<S>,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    mapping: Arc<HashMap<UserID, ecdsa::Public>>,
    role_id: ecdsa::Public,
    network: N,
) -> Result<Vec<u8>, JobError> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let local_key_share: KeyShare<E, S> = super::sign::get_key_share::<E, S>(serialized_key_share)?;
    let i = local_key_share.i;
    let n = local_key_share.public_shares.len() as u16;
    let t = local_key_share
        .vss_setup
        .as_ref()
        .map(|x| x.min_signers)
        .unwrap_or(n);

    logger.info(format!(
        "Starting KeyRefresh Protocol with params: i={i}, t={t}, n={n}"
    ));

    let job_id_bytes = job_id.to_be_bytes();
    let mix = keccak_256(b"dnfs-cggmp21-keyrefresh");
    let eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
    let eid = dfns_cggmp21::ExecutionId::new(&eid_bytes);

    let (
        key_refresh_tx_to_outbound,
        key_refresh_rx_async_proto,
        _broadcast_tx_to_outbound,
        _broadcast_rx_from_gadget,
    ) = gadget_common::channels::create_job_manager_to_async_protocol_channel_split_io::<
        _,
        (),
        Outgoing<aux_only::Msg<H, S>>,
        Incoming<aux_only::Msg<H, S>>,
    >(
        protocol_message_channel,
        associated_block_id,
        associated_retry_id,
        associated_session_id,
        associated_task_id,
        mapping.clone(),
        role_id,
        network.clone(),
        logger.clone(),
        i,
    );

    let mut tracer = dfns_cggmp21::progress::PerfProfiler::new();
    let delivery = (key_refresh_rx_async_proto, key_refresh_tx_to_outbound);
    let party = round_based_21::MpcParty::connected(delivery);
    let aux_info_builder =
        AuxInfoGenerationBuilder::<S, H>::new_aux_gen(eid, i, n, pregenerated_primes);
    let aux_info = aux_info_builder
        .set_progress_tracer(&mut tracer)
        .start(&mut rng, party)
        .await
        .map_err(|err| JobError {
            reason: format!("KeyRefresh protocol error: {err:?}"),
        })?;

    let key: KeyShare<E, S> = DirtyKeyShare::<E, S> {
        core: local_key_share.into_inner().core,
        aux: aux_info.into_inner(),
    }
    .validate()
    .map_err(|err| JobError {
        reason: format!("KeyRefresh protocol validation error: {err:?}"),
    })?;

    // let key = local_key_share
    //     .update_aux(aux_info)
    //     .map_err(|err| JobError {
    //         reason: format!("KeyRefresh protocol error: {err:?}"),
    //     })?;

    let perf_report = tracer.get_report().map_err(|err| JobError {
        reason: format!("KeyRefresh protocol error: {err:?}"),
    })?;
    logger.trace(format!("KeyRefresh protocol report: {perf_report}"));

    logger.debug("Finished AsyncProtocol - KeyRefresh");
    let serialized_local_key = serialize(&key).map_err(|err| JobError {
        reason: format!("KeyRefresh protocol error: {err:?}"),
    })?;
    Ok(serialized_local_key)
}
