use crate::protocols::util::{generate_party_key_ids, validate_parameters, FrostMessage, FrostState};
use futures::{SinkExt, StreamExt};
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::gadget::message::UserID;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::jobs::tss::{DKGTSSKeySubmissionResult, DigitalSignatureScheme};
use gadget_common::prelude::jobs::{JobResult, JobType};
use gadget_common::prelude::roles::tss::ThresholdSignatureRoleType;
use gadget_common::prelude::roles::RoleType;
use gadget_common::prelude::{DebugLogger, GadgetProtocolMessage, WorkManager};
use gadget_common::prelude::{ECDSAKeyStore, JobError};
use gadget_common::utils::recover_ecdsa_pub_key;
use gadget_common::{
    BuiltExecutableJobWrapper, JobBuilder, ProtocolWorkManager, WorkManagerInterface,
};
use hashbrown::HashMap;
use rand::{CryptoRng, RngCore};
use sp_core::{ecdsa, ByteArray, Pair, keccak_256};
use std::sync::Arc;
use itertools::Itertools;
use tangle_primitives::jobs::JobId;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;
use wsts::common::PolyCommitment;
use wsts::Scalar;
use wsts::v2::Party;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;

pub const K: u32 = 1;

#[derive(Clone)]
pub struct WstsKeygenExtraParams {
    job_id: JobId,
    n: u32,
    i: u32,
    k: u32,
    t: u32,
    user_id_mapping: Arc<std::collections::HashMap<UserID, ecdsa::Public>>,
    my_id: ecdsa::Public,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::WstsKeygenProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<WstsKeygenExtraParams, gadget_common::Error> {
    if let JobType::DKGTSSPhaseOne(p1_job) = job.job_type {
        let participants = job.participants_role_ids.clone();
        let user_id_to_account_id_mapping = Arc::new(
            participants
                .clone()
                .into_iter()
                .enumerate()
                .map(|r| (r.0 as UserID, r.1))
                .collect(),
        );

        let i = p1_job
            .participants
            .0
            .iter()
            .position(|p| p.0 == config.account_id.0)
            .expect("Should exist") as u16;

        let t = p1_job.threshold;
        let n = p1_job.participants.0.len() as u32;

        Ok(WstsKeygenExtraParams {
            job_id: job.job_id,
            n,
            i: i as _,
            k: n, // Each party will own exactly n keys for this protocol
            t: t as _,
            user_id_mapping: user_id_to_account_id_mapping,
            my_id: config.key_store.pair().public(),
        })
    } else {
        Err(gadget_common::Error::ClientError {
            err: "The supplied job is not a phase 1 job".to_string(),
        })
    }
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::WstsKeygenProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: WstsKeygenExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let result = Arc::new(Mutex::new(None));
    let result_clone = result.clone();
    let logger = config.logger.clone();
    let logger_clone = logger.clone();
    let network = config.clone();
    let keystore = config.key_store.clone();
    let keystore_clone = keystore.clone();
    let client = config.pallet_tx.clone();
    let WstsKeygenExtraParams {
        job_id,
        n,
        i,
        k,
        t,
        user_id_mapping,
        my_id,
    } = additional_params;

    let participants = user_id_mapping
        .keys()
        .copied()
        .map(|r| r as u8)
        .collect::<Vec<u8>>();

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
            let output = protocol(n, i, k, t, tx0, rx0, tx1, rx1, &logger, &keystore_clone).await?;
            result.lock().await.replace(output);

            Ok(())
        })
        .post(async move {
            if let Some((state, public_key, signatures)) = result_clone.lock().await.take() {
                keystore
                    .set_job_result(job_id, state)
                    .await
                    .map_err(|err| JobError {
                        reason: err.to_string(),
                    })?;

                let job_result_for_pallet = JobResult::DKGPhaseOne(DKGTSSKeySubmissionResult {
                    signature_scheme: DigitalSignatureScheme::SchnorrSecp256k1,
                    key: BoundedVec(public_key),
                    participants: BoundedVec(vec![BoundedVec(participants)]),
                    signatures: BoundedVec(signatures),
                    threshold: t as _,
                    __subxt_unused_type_params: Default::default(),
                });

                client
                    .submit_job_result(
                        RoleType::Tss(ThresholdSignatureRoleType::WstsV2),
                        job_id,
                        job_result_for_pallet,
                    )
                    .await
                    .map_err(|err| JobError {
                        reason: err.to_string(),
                    })?;
            }

            logger_clone.info("Finished AsyncProtocol - WSTS Keygen");
            Ok(())
        })
        .build())
}

/// `party_id`: Should be in the range [0, n). For the DKG, should be our index in the best
/// authorities starting from 0.
///
/// Returns the state of the party after the protocol has finished. This should be saved to the keystore and
/// later used for signing
#[allow(clippy::too_many_arguments)]
pub async fn protocol<KBE: KeystoreBackend>(
    n: u32,
    party_id: u32,
    k: u32,
    t: u32,
    tx_to_network: futures::channel::mpsc::UnboundedSender<FrostMessage>,
    rx_from_network: futures::channel::mpsc::UnboundedReceiver<std::io::Result<FrostMessage>>,
    tx_to_network_broadcast: tokio::sync::mpsc::UnboundedSender<FrostMessage>,
    mut rx_from_network_broadcast: UnboundedReceiver<FrostMessage>,
    logger: &DebugLogger,
    key_store: &ECDSAKeyStore<KBE>,
) -> Result<(FrostState, Vec<u8>, Vec<BoundedVec<u8>>), JobError> {
    validate_parameters(n, k, t)?;

    let mut rng = rand::rngs::OsRng;
    let key_ids = generate_party_key_ids(n, k);
    let our_key_ids = key_ids.get(party_id as usize).ok_or_else(|| JobError {
        reason: "Bad party_id".to_string(),
    })?;

    let mut party = Party::new(party_id, our_key_ids, n, k, t, &mut rng);
    let public_key = run_dkg(
        &mut party,
        &mut rng,
        n as usize,
        tx_to_network,
        rx_from_network,
        logger,
    )
    .await?;

    let party = party.save();
    logger.error(format!("Combined public key: {:?}", party.group_key));
    let our_combined_public_key = bincode2::serialize(&party.group_key).unwrap();

    // Sign this public key using our ECDSA key
    let hash_of_public_key = keccak_256(&our_combined_public_key);
    let signature_of_public_key = key_store.pair().sign_prehashed(&hash_of_public_key);

    // Gossip the public key
    let pkey_message = FrostMessage::PublicKeyBroadcast {
        party_id,
        combined_public_key: our_combined_public_key.clone(),
        signature_of_public_key: signature_of_public_key.clone(),
    };

    // Gossip the public key
    tx_to_network_broadcast
        .send(pkey_message)
        .map_err(|err| JobError {
            reason: format!("Error sending FROST message: {err:?}"),
        })?;

    let mut received = 0;
    let mut received_signatures = HashMap::new();
    received_signatures.insert(party_id, signature_of_public_key.clone());

    // We normally need t+1, however, we aren't verifying our own signature, thus collect t keys
    while received < t {
        let next_message = rx_from_network_broadcast
            .recv()
            .await
            .ok_or_else(|| JobError {
                reason: "broadcast stream died".to_string(),
            })?;
        match next_message {
            FrostMessage::PublicKeyBroadcast {
                party_id,
                combined_public_key,
                signature_of_public_key,
            } => {
                // Make sure their public key is equivalent to ours
                if combined_public_key.as_slice() != our_combined_public_key.as_slice() {
                    return Err(JobError { reason: format!("The received public key from party {party_id} does not match our public key. Aborting") });
                }

                // Verify the public key signature
                recover_ecdsa_pub_key(&our_combined_public_key, signature_of_public_key.as_slice())
                    .map_err(|_| JobError {
                        reason: format!("Failed to verify signature from party {party_id}"),
                    })?;

                received_signatures.insert(party_id, signature_of_public_key);
                received += 1;
            }

            message => {
                logger.warn(format!("Received improper message: {message:?}"));
            }
        }
    }

    let signatures = received_signatures
        .into_iter()
        .sorted_by_key(|k| k.0)
        .map(|r| BoundedVec(r.1 .0.to_vec()))
        .collect_vec();

    logger.info("Finished public key gossip");

    let frost_state = FrostState {
        public_key,
        party: Arc::new(party),
    };

    Ok((frost_state, our_combined_public_key, signatures))
}

pub async fn run_dkg<RNG: RngCore + CryptoRng>(
    signer: &mut Party,
    rng: &mut RNG,
    n_signers: usize,
    mut tx_to_network: futures::channel::mpsc::UnboundedSender<FrostMessage>,
    mut rx_from_network: futures::channel::mpsc::UnboundedReceiver<std::io::Result<FrostMessage>>,
    logger: &DebugLogger,
) -> Result<HashMap<u32, PolyCommitment>, JobError> {
    // Broadcast our party_id, shares, and key_ids to each other
    let party_id = signer.party_id;
    let shares: HashMap<u32, Scalar> = signer.get_shares().into_iter().collect();
    let key_ids = signer.key_ids.clone();
    logger.info(format!(
        "Our party ID: {party_id} | Our key IDS: {key_ids:?}"
    ));
    let poly_commitment = signer.get_poly_commitment(rng);

    let message = FrostMessage::Keygen {
        party_id,
        shares: shares.clone(),
        key_ids: key_ids.clone(),
        poly_commitment: poly_commitment.clone(),
    };

    // Send the message
    tx_to_network.send(message).await.map_err(|err| JobError {
        reason: format!("Error sending FROST message: {err:?}"),
    })?;

    let mut received_shares = HashMap::new();
    let mut received_key_ids = HashMap::new();
    let mut received_poly_commitments = HashMap::new();
    // insert our own shared into the received map
    received_shares.insert(party_id, shares);
    received_key_ids.insert(party_id, key_ids);
    received_poly_commitments.insert(party_id, poly_commitment);

    // Wait for n_signers to send their messages to us
    while received_shares.len() < n_signers {
        match rx_from_network.next().await {
            Some(Ok(FrostMessage::Keygen {
                party_id,
                shares,
                key_ids,
                poly_commitment,
            })) => {
                if party_id != signer.party_id {
                    logger.error(format!(
                        "Received shares from {party_id} with key ids: {key_ids:?}"
                    ));
                    received_shares.insert(party_id, shares);
                    received_key_ids.insert(party_id, key_ids);
                    received_poly_commitments.insert(party_id, poly_commitment);
                }
            }

            Some(evt) => logger.warn(format!("Received unexpected FROST event: {evt:?}")),

            None => {
                return Err(JobError {
                    reason: "NetListen connection died".to_string(),
                })
            }
        }
    }

    logger.trace(format!(
        "Received shares: {:?}",
        received_shares.keys().collect::<Vec<_>>()
    ));
    // Generate the party_shares: for each key id we own, we take our received key share at that
    // index
    let party_shares = signer
        .key_ids
        .iter()
        .copied()
        .map(|key_id| {
            let mut key_shares = HashMap::new();

            for (id, shares) in &received_shares {
                key_shares.insert(*id, shares[&key_id]);
            }

            (key_id, key_shares.into_iter().collect())
        })
        .collect();
    let polys = received_poly_commitments
        .iter()
        .sorted_by(|a, b| a.0.cmp(b.0))
        .map(|r| r.1.clone())
        .collect_vec();

    signer
        .compute_secret(&party_shares, &polys)
        .map_err(|err| JobError {
            reason: err.to_string(),
        })?;

    logger.info("Keygen finished computing secret");
    Ok(received_poly_commitments)
}
