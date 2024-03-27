use derivation_path::DerivationPath;

use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::*;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use gadget_common::channels;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::group::GroupEncoding;
use rand::SeedableRng;
use round_based_21::{Incoming, MpcParty, Outgoing};
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::rounds;
use crate::rounds::keygen::SilentShardDKLS23KeyShare;
use crate::rounds::sign::Msg;

#[derive(Clone)]
pub struct SilentShardDKLS23SigningExtraParams {
    pub i: u16,
    pub t: u16,
    pub signers: Vec<u16>,
    pub job_id: u64,
    pub role_type: roles::RoleType,
    pub key_share: SilentShardDKLS23KeyShare,
    pub derivation_path: DerivationPath,
    pub input_data_to_sign: Vec<u8>,
    pub user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentShardDKLS23SigningProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<SilentShardDKLS23SigningExtraParams, gadget_common::Error> {
    let job_id = job.job_id;

    let jobs::JobType::DKGTSSPhaseTwo(p2_job) = job.job_type else {
        panic!("Should be valid type")
    };
    let input_data_to_sign = p2_job.submission.0.to_vec();
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

    let params = SilentShardDKLS23SigningExtraParams {
        i,
        t,
        signers,
        job_id,
        role_type: job.role_type,
        key_share: key,
        derivation_path: DerivationPath::from_str("m").unwrap(),
        input_data_to_sign,
        user_id_to_account_id_mapping,
    };
    Ok(params)
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentShardDKLS23SigningProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: SilentShardDKLS23SigningExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let debug_logger_post = config.logger.clone();
    let logger = debug_logger_post.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let pallet_tx = config.pallet_tx.clone();
    let id = config.key_store.pair().public();
    let network = config.clone();

    let (i, signers, t, key_share, derivation_path, _role_type, input_data_to_sign, mapping) = (
        additional_params.i,
        additional_params.signers,
        additional_params.t,
        additional_params.key_share,
        additional_params.derivation_path,
        additional_params.role_type.clone(),
        additional_params.input_data_to_sign.clone(),
        additional_params.user_id_to_account_id_mapping.clone(),
    );

    let verifying_key = key_share.verifying_key;
    let input_data_to_sign2 = input_data_to_sign.clone();

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
            let data_hash = keccak_256(input_data_to_sign.as_slice());
            let signature = rounds::sign::run_threshold_sign(
                Some(&mut tracer),
                i,
                signers,
                key_share,
                derivation_path,
                &data_hash,
                &mut rng,
                party,
            )
            .await
            .map_err(|err| JobError {
                reason: format!("Signing protocol error: {err:?}"),
            })?;
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
                // let (signature, data_hash) = convert_ecdsa_signature(
                //     signature.group_signature.to_bytes().to_vec(),
                //     &input_data_to_sign2,
                //     &verifying_key.to_bytes(),
                // );
                let data_hash = keccak_256(input_data_to_sign2.as_slice());
                let signature = signature.group_signature.to_bytes().to_vec();
                println!("Verifying key: {:?}", verifying_key);
                let res = VerifyingKey::from_affine(verifying_key)
                    .map(|vk| {
                        vk.verify_prehash(&data_hash, &Signature::from_slice(&signature).unwrap())
                    })
                    .map_err(|e| JobError {
                        reason: format!("Failed to verify signature: {e:?}"),
                    })?;
                println!("Signature verification result: {:?}", res);

                println!("Signature: {:?}", signature);
                let job_result = jobs::JobResult::DKGPhaseTwo(jobs::tss::DKGTSSSignatureResult {
                    signature_scheme: jobs::tss::DigitalSignatureScheme::EcdsaSecp256k1,
                    data: BoundedVec(data_hash.to_vec()),
                    signature: BoundedVec(signature.to_vec()),
                    verifying_key: BoundedVec(verifying_key.to_bytes().to_vec()),
                    derivation_path: None,
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
            } else {
                println!("No signature was found");
            }

            Ok(())
        })
        .build())
}

pub fn convert_ecdsa_signature(
    signature: Vec<u8>,
    data: &[u8],
    public_key_bytes: &[u8],
) -> ([u8; 65], [u8; 32]) {
    let mut signature_bytes = [0u8; 65];
    (signature_bytes[..64]).copy_from_slice(&signature[..64]);
    let data_hash = keccak_256(data);
    // To figure out the recovery ID, we need to try all possible values of v
    // in our case, v can be 0 or 1
    let mut v = 0u8;
    loop {
        let mut signature_bytes = signature_bytes;
        signature_bytes[64] = v;
        let res = sp_io::crypto::secp256k1_ecdsa_recover(&signature_bytes, &data_hash);
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
    (signature_bytes, data_hash)
}
