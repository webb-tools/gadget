use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Ed25519Sha512;
use frost_ed448::Ed448Shake256;
use frost_p256::P256Sha256;
use frost_p384::P384Sha384;
use frost_ristretto255::Ristretto255Sha512;
use frost_secp256k1::Secp256K1Sha256;
use gadget_common::channels;
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use rand::SeedableRng;
use round_based_21::{Incoming, MpcParty, Outgoing};
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::rounds;
use crate::rounds::keygen::FrostKeyShare;
use crate::rounds::sign::Msg;

#[derive(Clone)]
pub struct ZcashFrostSigningExtraParams {
    pub i: u16,
    pub t: u16,
    pub signers: Vec<u16>,
    pub job_id: u64,
    pub role_type: roles::RoleType,
    pub key_share: FrostKeyShare,
    pub input_data_to_sign: Vec<u8>,
    pub user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn create_next_job<C: ClientWithApi, N: Network, KBE: KeystoreBackend>(
    config: &crate::ZcashFrostSigningProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<ZcashFrostSigningExtraParams, gadget_common::Error> {
    let job_id = job.job_id;

    let jobs::JobType::DKGTSSPhaseTwo(p2_job) = job.job_type else {
        panic!("Should be valid type")
    };
    let input_data_to_sign = p2_job.submission.0;
    let previous_job_id = p2_job.phase_one_id;

    let phase1_job = job.phase1_job.expect("Should exist for a phase 2 job");
    let participants = job.participants_role_ids;
    let t = phase1_job.get_threshold().expect("Should exist") as u16;

    let seed = keccak_256(&[&job_id.to_be_bytes()[..], &job.retry_id.to_be_bytes()[..]].concat());
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
    let id = config.key_store.pair().public();

    let (i, signers, mapping) = super::util::choose_signers(&mut rng, &id, &participants, t)?;
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

    let params = ZcashFrostSigningExtraParams {
        i,
        t,
        signers,
        job_id,
        role_type: job.role_type,
        key_share: key,
        input_data_to_sign,
        user_id_to_account_id_mapping,
    };
    Ok(params)
}

macro_rules! deserialize_and_run_threshold_sign {
    ($impl_type:ty, $key_share:expr, $tracer:expr, $i:expr, $signers:expr, $msg:expr, $role:expr, $rng:expr, $party:expr) => {{
        let key_package =
            KeyPackage::<$impl_type>::deserialize(&$key_share.key_package).map_err(|err| {
                JobError {
                    reason: format!("Failed to deserialize key share: {err:?}"),
                }
            })?;

        let public_key_package = PublicKeyPackage::<$impl_type>::deserialize(
            &$key_share.pubkey_package,
        )
        .map_err(|err| JobError {
            reason: format!("Failed to deserialize public key package: {err:?}"),
        })?;

        rounds::sign::run_threshold_sign(
            Some($tracer),
            $i,
            $signers,
            (key_package, public_key_package),
            $msg,
            $role,
            $rng,
            $party,
        )
        .await
        .map_err(|err| JobError {
            reason: format!("Failed to run threshold sign: {err:?}"),
        })?
    }};
}

pub async fn generate_protocol_from<C: ClientWithApi, N: Network, KBE: KeystoreBackend>(
    config: &crate::ZcashFrostSigningProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: ZcashFrostSigningExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let debug_logger_post = config.logger.clone();
    let logger = debug_logger_post.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let pallet_tx = config.pallet_tx.clone();
    let id = config.key_store.pair().public();
    let network = config.clone();

    let (i, signers, t, key_share, role_type, input_data_to_sign, mapping) = (
        additional_params.i,
        additional_params.signers,
        additional_params.t,
        additional_params.key_share,
        additional_params.role_type.clone(),
        additional_params.input_data_to_sign.clone(),
        additional_params.user_id_to_account_id_mapping.clone(),
    );

    let role = match role_type {
        roles::RoleType::Tss(role) => role.clone(),
        _ => {
            return Err(JobError {
                reason: "Invalid role type".to_string(),
            })
        }
    };

    let role2 = role.clone();

    Ok(JobBuilder::new()
        .protocol(async move {
            let mut rng = rand::rngs::StdRng::from_entropy();
            logger.info(format!(
                "Starting Signing Protocol with params: i={i}, t={t}"
            ));

            let (
                signing_tx_to_outbound,
                signing_rx_async_proto,
                _broadcast_tx_to_outbound,
                _broadcast_rx_from_gadget,
            ) = channels::create_job_manager_to_async_protocol_channel_split_io::<
                _,
                (),
                Outgoing<Msg>,
                Incoming<Msg>,
            >(
                protocol_message_channel,
                associated_block_id,
                associated_retry_id,
                associated_session_id,
                associated_task_id,
                mapping.clone(),
                id,
                network.clone(),
                logger.clone(),
                i,
            );

            let mut tracer = dfns_cggmp21::progress::PerfProfiler::new();
            let delivery = (signing_rx_async_proto, signing_tx_to_outbound);
            let party = MpcParty::connected(delivery);
            let signature = match role {
                roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1 => {
                    deserialize_and_run_threshold_sign!(
                        Secp256K1Sha256,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519 => {
                    deserialize_and_run_threshold_sign!(
                        Ed25519Sha512,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448 => {
                    deserialize_and_run_threshold_sign!(
                        Ed448Shake256,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostP256 => {
                    deserialize_and_run_threshold_sign!(
                        P256Sha256,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostP384 => {
                    deserialize_and_run_threshold_sign!(
                        P384Sha384,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255 => {
                    deserialize_and_run_threshold_sign!(
                        Ristretto255Sha512,
                        key_share,
                        &mut tracer,
                        i,
                        signers,
                        &input_data_to_sign,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                _ => {
                    return Err(JobError {
                        reason: "Invalid role type".to_string(),
                    })
                }
            };
            let perf_report = tracer.get_report().map_err(|err| JobError {
                reason: format!("Signing protocol error: {err:?}"),
            })?;
            logger.trace(format!("Signing protocol report: {perf_report}"));
            logger.debug("Finished AsyncProtocol - Signing");
            *protocol_output.lock().await = Some(signature);
            Ok(())
        })
        .post(async move {
            // Submit the protocol output to the blockchain
            if let Some(signature) = protocol_output_clone.lock().await.take() {
                // Compute the signature bytes by first converting the signature
                // to a fixed byte array and then converting that to a Vec<u8>.
                let (signature, signature_scheme) = match role2 {
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1 => {
                        let mut signature_bytes = [0u8; 65];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrSecp256k1,
                        )
                    }
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519 => {
                        let mut signature_bytes = [0u8; 64];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrEd25519,
                        )
                    }
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448 => {
                        let mut signature_bytes = [0u8; 114];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrEd448,
                        )
                    }
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostP256 => {
                        let mut signature_bytes = [0u8; 65];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrP256,
                        )
                    }
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostP384 => {
                        let mut signature_bytes = [0u8; 97];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrP384,
                        )
                    }
                    roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255 => {
                        let mut signature_bytes = [0u8; 64];
                        signature_bytes.copy_from_slice(&signature.group_signature);
                        (
                            signature_bytes.to_vec(),
                            jobs::tss::DigitalSignatureScheme::SchnorrRistretto255,
                        )
                    }
                    _ => {
                        return Err(JobError {
                            reason: "Invalid role type".to_string(),
                        })
                    }
                };

                let job_result = jobs::JobResult::DKGPhaseTwo(jobs::tss::DKGTSSSignatureResult {
                    signature_scheme,
                    derivation_path: None,
                    data: BoundedVec(additional_params.input_data_to_sign),
                    signature: BoundedVec(signature),
                    verifying_key: BoundedVec(Default::default()),
                    __subxt_unused_type_params: Default::default(),
                });

                pallet_tx
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
