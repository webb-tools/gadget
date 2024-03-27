use frost_ed25519::Ed25519Sha512;
use frost_ed448::Ed448Shake256;
use frost_p256::P256Sha256;
use frost_p384::P384Sha384;
use frost_ristretto255::Ristretto255Sha512;
use frost_secp256k1::Secp256K1Sha256;
use futures::StreamExt;
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;
use gadget_common::debug_logger::DebugLogger;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::{ECDSAKeyStore, KeystoreBackend};
use gadget_common::prelude::*;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::{MaxParticipants, MaxKeyLen, MaxProofLen, MaxDataLen, MaxSignatureLen};

use gadget_common::{channels, utils};
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use itertools::Itertools;
use rand::SeedableRng;
use round_based_21::{Incoming, Outgoing};
use sp_core::{ecdsa, keccak_256, Pair};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::rounds;
use crate::rounds::keygen::Msg;
use gadget_common::channels::PublicKeyGossipMessage;

#[derive(Clone)]
pub struct ZcashFrostKeygenExtraParams {
    pub i: u16,
    pub t: u16,
    pub n: u16,
    pub job_id: u64,
    pub role_type: roles::RoleType,
    pub user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn create_next_job<C: ClientWithApi, N: Network, KBE: KeystoreBackend>(
    config: &crate::ZcashFrostKeygenProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<ZcashFrostKeygenExtraParams, gadget_common::Error> {
    let job_id = job.job_id;
    let role_type = job.job_type.get_role_type();

    // We can safely make this assumption because we are only creating jobs for phase one
    let jobs::JobType::DKGTSSPhaseOne(p1_job) = job.job_type else {
        panic!("Should be valid type")
    };

    let participants = job.participants_role_ids;
    let threshold = p1_job.threshold;

    let user_id_to_account_id_mapping = Arc::new(
        participants
            .clone()
            .into_iter()
            .enumerate()
            .map(|r| (r.0 as UserID, r.1))
            .collect(),
    );

    let id = config.key_store.pair().public();

    let params = ZcashFrostKeygenExtraParams {
        i: participants
            .iter()
            .position(|p| p == &id)
            .expect("Should exist") as u16,
        t: threshold as u16,
        n: participants.len() as u16,
        role_type,
        job_id,
        user_id_to_account_id_mapping,
    };

    Ok(params)
}

macro_rules! run_threshold_keygen {
    ($impl_type:ty, $tracer:expr, $i:expr, $t:expr, $n:expr, $role:expr, $rng:expr, $party:expr) => {
        rounds::keygen::run_threshold_keygen::<$impl_type, _, _>(
            Some($tracer),
            $i,
            $t,
            $n,
            $role,
            $rng,
            $party,
        )
        .await
        .map_err(|err| {
            println!("Keygen protocol error: {err:#?}");
            err.to_string()
        })?
    };
}

pub async fn generate_protocol_from<C: ClientWithApi, N: Network, KBE: KeystoreBackend>(
    config: &crate::ZcashFrostKeygenProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: ZcashFrostKeygenExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let key_store = config.key_store.clone();
    let key_store2 = config.key_store.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let pallet_tx = config.pallet_tx.clone();
    let id = config.key_store.pair().public();
    let logger = config.logger.clone();
    let network = config.clone();

    let (i, t, n, mapping, role_type) = (
        additional_params.i,
        additional_params.t,
        additional_params.n,
        additional_params.user_id_to_account_id_mapping,
        additional_params.role_type.clone(),
    );

    let role = match role_type {
        roles::RoleType::Tss(role) => role,
        _ => {
            return Err(JobError {
                reason: "Invalid role type".to_string(),
            })
        }
    };

    Ok(JobBuilder::new()
        .protocol(async move {
            let mut rng = rand::rngs::StdRng::from_entropy();
            logger.info(format!(
                "Starting Keygen Protocol with params: i={i}, t={t}, n={n}"
            ));

            let (
                keygen_tx_to_outbound,
                keygen_rx_async_proto,
                broadcast_tx_to_outbound,
                broadcast_rx_from_gadget,
            ) = channels::create_job_manager_to_async_protocol_channel_split_io::<
                _,
                _,
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
            let delivery = (keygen_rx_async_proto, keygen_tx_to_outbound);
            let party = round_based_21::MpcParty::connected(delivery);
            let frost_key_share_package = match role {
                roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519 => {
                    run_threshold_keygen!(
                        Ed25519Sha512,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448 => {
                    run_threshold_keygen!(
                        Ed448Shake256,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostP256 => {
                    run_threshold_keygen!(
                        P256Sha256,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostP384 => {
                    run_threshold_keygen!(
                        P384Sha384,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255 => {
                    run_threshold_keygen!(
                        Ristretto255Sha512,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1 => {
                    run_threshold_keygen!(
                        Secp256K1Sha256,
                        &mut tracer,
                        i,
                        t,
                        n,
                        role.clone(),
                        &mut rng,
                        party
                    )
                }
                _ => unreachable!("Invalid role"),
            };
            let perf_report = tracer.get_report().map_err(|err| JobError {
                reason: format!("Keygen protocol error: {err:?}"),
            })?;
            logger.trace(format!("Incomplete Keygen protocol report: {perf_report}"));
            logger.debug("Finished AsyncProtocol - Incomplete Keygen");

            let job_result = handle_public_key_gossip(
                key_store2,
                &logger,
                &frost_key_share_package.verifying_key,
                role.clone(),
                t,
                i,
                broadcast_tx_to_outbound,
                broadcast_rx_from_gadget,
            )
            .await?;

            *protocol_output.lock().await = Some((frost_key_share_package, job_result));
            Ok(())
        })
        .post(async move {
            // TODO: handle protocol blames
            // Store the keys locally, as well as submitting them to the blockchain
            if let Some((local_key, job_result)) = protocol_output_clone.lock().await.take() {
                key_store
                    .set_job_result(additional_params.job_id, local_key)
                    .await
                    .map_err(|err| JobError {
                        reason: format!("Failed to store key: {err:?}"),
                    })?;

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

#[allow(clippy::too_many_arguments)]
async fn handle_public_key_gossip<KBE: KeystoreBackend>(
    key_store: ECDSAKeyStore<KBE>,
    logger: &DebugLogger,
    public_key_package: &[u8],
    role: roles::tss::ThresholdSignatureRoleType,
    t: u16,
    i: u16,
    broadcast_tx_to_outbound: futures::channel::mpsc::UnboundedSender<PublicKeyGossipMessage>,
    mut broadcast_rx_from_gadget: futures::channel::mpsc::UnboundedReceiver<PublicKeyGossipMessage>,
) -> Result<
    jobs::JobResult<
        MaxParticipants,
        MaxKeyLen,
        MaxSignatureLen,
        MaxDataLen,
        MaxProofLen,
        MaxAdditionalParamsLen,
    >,
    JobError,
> {
    let key_hashed = keccak_256(public_key_package);
    let signature = key_store.pair().sign_prehashed(&key_hashed).0.to_vec();
    let my_id = key_store.pair().public();
    let mut received_keys = BTreeMap::new();
    received_keys.insert(i, signature.clone());
    let mut received_participants = BTreeMap::new();
    received_participants.insert(i, my_id);

    broadcast_tx_to_outbound
        .unbounded_send(PublicKeyGossipMessage {
            from: i as _,
            to: None,
            signature,
            id: my_id,
        })
        .map_err(|err| JobError {
            reason: format!("Failed to send public key: {err:?}"),
        })?;

    for _ in 0..t {
        let message = broadcast_rx_from_gadget
            .next()
            .await
            .ok_or_else(|| JobError {
                reason: "Failed to receive public key".to_string(),
            })?;

        let from = message.from;
        logger.debug(format!("Received public key from {from}"));

        if received_keys.contains_key(&(from as u16)) {
            logger.warn("Received duplicate key");
            continue;
        }
        // verify signature
        let maybe_signature = sp_core::ecdsa::Signature::from_slice(&message.signature);
        match maybe_signature.and_then(|s| s.recover_prehashed(&key_hashed)) {
            Some(p) if p != message.id => {
                logger.warn(format!(
                    "Received invalid signature from {from} not signed by them"
                ));
            }
            Some(p) if p == message.id => {
                logger.debug(format!("Received valid signature from {from}"));
            }
            Some(_) => unreachable!("Should not happen"),
            None => {
                logger.warn(format!("Received invalid signature from {from}"));
                continue;
            }
        }

        received_keys.insert(from as u16, message.signature);
        received_participants.insert(from as u16, message.id);
        logger.debug(format!(
            "Received {}/{} signatures",
            received_keys.len(),
            t + 1
        ));
    }

    // Order and collect the map to ensure symmetric submission to blockchain
    let signatures = received_keys
        .into_iter()
        .sorted_by_key(|x| x.0)
        .map(|(_, p)| BoundedVec(p))
        .collect::<Vec<_>>();

    let participants = BoundedVec(
        received_participants
            .into_iter()
            .sorted_by_key(|x| x.0)
            .map(|(_, p)| BoundedVec(p.0.to_vec()))
            .collect::<Vec<_>>(),
    );

    if signatures.len() < t as usize {
        return Err(JobError {
            reason: format!(
                "Received {} signatures, expected at least {}",
                signatures.len(),
                t + 1,
            ),
        });
    }

    let res = jobs::tss::DKGTSSKeySubmissionResult {
        signature_scheme: match role {
            roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519 => {
                jobs::tss::DigitalSignatureScheme::SchnorrEd25519
            }
            roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448 => {
                jobs::tss::DigitalSignatureScheme::SchnorrEd448
            }
            roles::tss::ThresholdSignatureRoleType::ZcashFrostP256 => {
                jobs::tss::DigitalSignatureScheme::SchnorrP256
            }
            roles::tss::ThresholdSignatureRoleType::ZcashFrostP384 => {
                jobs::tss::DigitalSignatureScheme::SchnorrP384
            }
            roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255 => {
                jobs::tss::DigitalSignatureScheme::SchnorrRistretto255
            }
            roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1 => {
                jobs::tss::DigitalSignatureScheme::SchnorrSecp256k1
            }
            _ => unreachable!("Invalid role"),
        },
        key: BoundedVec(public_key_package.to_vec()),
        participants,
        signatures: BoundedVec(signatures),
        threshold: t as _,
        __subxt_unused_type_params: Default::default(),
    };
    verify_generated_dkg_key_ecdsa(res.clone(), logger);
    Ok(jobs::JobResult::DKGPhaseOne(res))
}

fn verify_generated_dkg_key_ecdsa(
    data: jobs::tss::DKGTSSKeySubmissionResult<MaxKeyLen, MaxParticipants, MaxSignatureLen>,
    logger: &DebugLogger,
) {
    // Ensure participants and signatures are not empty
    assert!(!data.participants.0.is_empty(), "NoParticipantsFound",);
    assert!(!data.signatures.0.is_empty(), "NoSignaturesFound");

    // Generate the required ECDSA signers
    let maybe_signers = data
        .participants
        .0
        .iter()
        .map(|x| {
            ecdsa::Public(
                utils::to_slice_33(&x.0)
                    .unwrap_or_else(|| panic!("Failed to convert input to ecdsa public key")),
            )
        })
        .collect::<Vec<ecdsa::Public>>();

    assert!(!maybe_signers.is_empty(), "NoParticipantsFound");

    let mut known_signers: Vec<ecdsa::Public> = Default::default();

    for signature in data.signatures.0 {
        // Ensure the required signer signature exists
        let (maybe_authority, success) =
            utils::verify_signer_from_set_ecdsa(maybe_signers.clone(), &data.key.0, &signature.0);

        if success {
            let authority = maybe_authority.expect("CannotRetreiveSigner");

            // Ensure no duplicate signatures
            assert!(!known_signers.contains(&authority), "DuplicateSignature");

            logger.debug(format!("Verified signature from {}", authority));
            known_signers.push(authority);
        }
    }

    // Ensure a sufficient number of unique signers are present
    assert!(
        known_signers.len() > data.threshold as usize,
        "NotEnoughSigners"
    );
    logger.debug(format!(
        "Verified {}/{} signatures",
        known_signers.len(),
        data.threshold + 1
    ));
}
