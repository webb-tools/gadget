use crate::protocols::util::{FrostMessage, FrostState};
use futures::{SinkExt, StreamExt};
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::gadget::message::UserID;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::jobs::tss::{
    DKGTSSPhaseOneJobType, DKGTSSPhaseTwoJobType, DKGTSSSignatureResult, DigitalSignatureScheme,
};
use gadget_common::prelude::jobs::{JobResult, JobType};
use gadget_common::prelude::roles::tss::ThresholdSignatureRoleType;
use gadget_common::prelude::roles::RoleType;
use gadget_common::prelude::{DebugLogger, GadgetProtocolMessage, WorkManager};
use gadget_common::{
    BuiltExecutableJobWrapper, JobBuilder, JobError, ProtocolWorkManager, WorkManagerInterface,
};
use hashbrown::HashMap;
use itertools::Itertools;
use rand::rngs::ThreadRng;
use sp_core::{ecdsa, keccak_256, Pair};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use wsts::common::Signature;
use wsts::Point;
use wsts::v2::{Party, SignatureAggregator};
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;

#[derive(Clone)]
pub struct WstsSigningExtraParams {
    user_id_mapping: Arc<std::collections::HashMap<UserID, ecdsa::Public>>,
    my_id: ecdsa::Public,
    keygen_state: FrostState,
    message_to_sign: Vec<u8>,
    k: u32,
    t: u32,
    job_id: u64,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::WstsSigningProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<WstsSigningExtraParams, gadget_common::Error> {
    let job_id = job.job_id;
    if let Some(JobType::DKGTSSPhaseOne(DKGTSSPhaseOneJobType {
        participants: _,
        threshold,
        permitted_caller: _,
        role_type: _,
        ..
    })) = job.phase1_job
    {
        let participants = job.participants_role_ids.clone();
        let n = participants.len();
        let user_id_to_account_id_mapping = Arc::new(
            participants
                .clone()
                .into_iter()
                .enumerate()
                .map(|r| (r.0 as UserID, r.1))
                .collect(),
        );

        let JobType::DKGTSSPhaseTwo(DKGTSSPhaseTwoJobType {
            phase_one_id,
            submission,
            derivation_path: _,
            role_type: _,
            __subxt_unused_type_params,
        }) = job.job_type
        else {
            panic!("Invalid job type for WSTS signing")
        };
        let my_id = config.key_store.pair().public();
        let keygen_state = config
            .key_store
            .get_job_result(phase_one_id)
            .await?
            .ok_or_else(|| gadget_common::Error::ClientError {
                err: format!("Unable to find stored job result for previous job {phase_one_id}"),
            })?;

        Ok(WstsSigningExtraParams {
            user_id_mapping: user_id_to_account_id_mapping,
            my_id,
            keygen_state,
            message_to_sign: submission.0,
            k: n as _,
            t: threshold as _,
            job_id,
        })
    } else {
        Err(gadget_common::Error::ClientError {
            err: "Invalid job type".to_string(),
        })
    }
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::WstsSigningProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: WstsSigningExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let result = Arc::new(tokio::sync::Mutex::new(None));
    let result_clone = result.clone();
    let network = config.clone();
    let logger = config.logger.clone();
    let logger_clone = logger.clone();
    let client = config.pallet_tx.clone();

    let WstsSigningExtraParams {
        user_id_mapping,
        my_id,
        keygen_state,
        message_to_sign,
        k,
        t,
        job_id,
    } = additional_params;

    let data_to_sign = message_to_sign.clone();
    // let verifying_key = keygen_state.public_key.clone();

    Ok(JobBuilder::new()
        .protocol(async move {
            let (tx0, rx0, tx1, rx1) =
                gadget_common::channels::create_job_manager_to_async_protocol_channel_split::<
                    _,
                    FrostMessage,
                    FrostMessage,
                >(
                    protocol_message_channel,
                    associated_block_id,
                    associated_retry_id,
                    associated_session_id,
                    associated_task_id,
                    user_id_mapping,
                    my_id,
                    network,
                    logger.clone(),
                );

            let signature = run_signing(
                keygen_state,
                &message_to_sign,
                k,
                t,
                tx0,
                rx0,
                tx1,
                rx1,
                &logger,
            )
            .await?;
            result.lock().await.replace(signature);
            Ok(())
        })
        .post(async move {
            if let Some((aggregated_public_key, signature)) = result_clone.lock().await.take() {
                let serializable_form = (signature.R, signature.z);

                let serialized_signature = bincode2::serialize(&serializable_form).unwrap();
                // let serialized_verifying_key = bincode2::serialize(&verifying_key).unwrap();
                let serialized_verifying_key = bincode2::serialize(&aggregated_public_key).unwrap();
                logger_clone.info(format!(
                    "Serialized public key Len: {} | First 3 bytes: {:?} | Last 3 bytes: {:?}",
                    serialized_verifying_key.len(),
                    &serialized_verifying_key[..3],
                    &serialized_verifying_key[serialized_verifying_key.len() - 3..]
                ));
                let job_result = JobResult::DKGPhaseTwo(DKGTSSSignatureResult {
                    signature_scheme: DigitalSignatureScheme::WstsV2,
                    derivation_path: None,
                    data: BoundedVec(data_to_sign),
                    signature: BoundedVec(serialized_signature),
                    verifying_key: BoundedVec(serialized_verifying_key),
                    __subxt_unused_type_params: Default::default(),
                });

                client
                    .submit_job_result(
                        RoleType::Tss(ThresholdSignatureRoleType::WstsV2),
                        job_id,
                        job_result,
                    )
                    .await
                    .map_err(|err| JobError {
                        reason: format!("Error submitting job result: {err:?}"),
                    })?;
            }

            Ok(())
        })
        .build())
}

/// `threshold`: Should be the number of participants in this round, since we stop looking for
/// messages after finding the first `t` messages
#[allow(clippy::too_many_arguments)]
pub async fn run_signing(
    state: FrostState,
    msg: &[u8],
    num_keys: u32,
    threshold: u32,
    mut tx_to_network: futures::channel::mpsc::UnboundedSender<FrostMessage>,
    mut rx_from_network: futures::channel::mpsc::UnboundedReceiver<std::io::Result<FrostMessage>>,
    tx_to_network_final: tokio::sync::mpsc::UnboundedSender<FrostMessage>,
    mut rx_from_network_final: tokio::sync::mpsc::UnboundedReceiver<FrostMessage>,
    logger: &DebugLogger,
) -> Result<(Point, Signature), JobError> {
    let mut signer = Party::load(&state.party);
    let public_key_point = state.party.group_key;
    let public_key = state.public_key;
    // Broadcast the party_id, key_ids, and nonce to each other
    let nonce = {
        let rng = &mut ThreadRng::default();
        signer.gen_nonce(rng)
    };
    let party_id = signer.party_id;
    let key_ids = signer.key_ids.clone();
    let message = FrostMessage::Signing {
        party_id,
        key_ids: key_ids.clone(),
        nonce: nonce.clone(),
    };

    // Send the message
    tx_to_network.send(message).await.map_err(|err| JobError {
        reason: format!("Error sending FROST message: {err:?}"),
    })?;

    let mut party_key_ids = HashMap::new();
    let mut party_nonces = HashMap::new();

    party_key_ids.insert(party_id, key_ids);
    party_nonces.insert(party_id, nonce);

    // We need t+1 sigs
    while party_nonces.len() < (threshold + 1) as usize {
        match rx_from_network.next().await {
            Some(Ok(FrostMessage::Signing {
                party_id: party_id_recv,
                key_ids,
                nonce,
            })) => {
                if party_id != party_id_recv {
                    party_key_ids.insert(party_id_recv, key_ids);
                    party_nonces.insert(party_id_recv, nonce);
                }
            }

            Some(evt) => {
                logger.warn(format!("Received unexpected FROST signing event: {evt:?}"));
            }

            None => {
                return Err(JobError {
                    reason: "NetListen connection died".to_string(),
                })
            }
        }
    }

    // Sort the vecs
    let party_ids = party_key_ids
        .keys()
        .copied()
        .sorted_by(|a, b| a.cmp(b))
        .collect_vec();
    let party_key_ids = party_key_ids
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .flat_map(|r| r.1)
        .collect_vec();
    let party_nonces = party_nonces
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .map(|r| r.1)
        .collect_vec();

    // Generate our signature share. We sign a hash of the message
    let msg = keccak_256(msg);
    let signature_share = signer.sign(&msg, &party_ids, &party_key_ids, &party_nonces);
    let message = FrostMessage::SigningFinal {
        party_id,
        signature_share: signature_share.clone(),
    };
    // Broadcast our signature share to each other
    tx_to_network_final.send(message).map_err(|err| JobError {
        reason: format!("Error sending FROST message: {err:?}"),
    })?;

    let mut signature_shares = HashMap::new();
    signature_shares.insert(party_id, signature_share.clone());

    // Receive t + 1 number of shares
    while signature_shares.len() < (threshold + 1) as usize {
        match rx_from_network_final.recv().await {
            Some(FrostMessage::SigningFinal {
                party_id: party_id_recv,
                signature_share,
            }) => {
                if party_id != party_id_recv {
                    signature_shares.insert(party_id_recv, signature_share);
                }
            }

            Some(evt) => {
                logger.warn(format!(
                    "Received unexpected FROST signing final event: {evt:?}"
                ));
            }

            None => {
                return Err(JobError {
                    reason: "NetListen connection died".to_string(),
                })
            }
        }
    }

    // Sort the signature shares
    let signature_shares = signature_shares
        .into_iter()
        .sorted_by(|a, b| a.0.cmp(&b.0))
        .map(|r| r.1)
        .collect_vec();

    let public_key = public_key
        .into_iter()
        .sorted_by(|r1, r2| r1.0.cmp(&r2.0))
        .map(|r| r.1)
        .collect_vec();

    // Aggregate and sign to generate the signature
    let mut sig_agg =
        SignatureAggregator::new(num_keys, threshold, public_key).map_err(|err| JobError {
            reason: err.to_string(),
        })?;
    /*sig_agg.init(&public_key).map_err(|err| JobError {
        reason: err.to_string(),
    })?; Commented out for use in later versions of WSTS*/

    sig_agg
        .sign(&msg, &party_nonces, &signature_shares, &party_key_ids)
        .map_err(|err| JobError {
            reason: err.to_string(),
        })
        .map(|r| (public_key_point, r))
}
