use dfns_cggmp21::generic_ec::Curve;
use dfns_cggmp21::key_refresh::msg::aux_only;
use dfns_cggmp21::key_refresh::AuxInfoGenerationBuilder;
use dfns_cggmp21::key_share::DirtyKeyShare;
use dfns_cggmp21::key_share::Validate;
use dfns_cggmp21::keygen::msg::threshold::Msg;
use dfns_cggmp21::keygen::KeygenBuilder;
use dfns_cggmp21::progress::PerfProfiler;
use dfns_cggmp21::security_level::SecurityLevel;
use dfns_cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use dfns_cggmp21::KeyShare;
use dfns_cggmp21::PregeneratedPrimes;
use digest::typenum::U32;
use digest::Digest;
use futures::channel::mpsc::{TryRecvError, UnboundedSender};
use futures::StreamExt;
use gadget_common::client::ClientWithApi;
use gadget_common::debug_logger::DebugLogger;
use gadget_common::full_protocol::FullProtocolConfig;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::{ECDSAKeyStore, KeystoreBackend};
use gadget_common::utils::{deserialize, serialize};
use gadget_common::{prelude::*, tangle_runtime::*, utils};
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use itertools::Itertools;
use rand::rngs::{OsRng, StdRng};
use rand::{CryptoRng, RngCore, SeedableRng};
use round_based_21::{Delivery, Incoming, MpcParty, Outgoing};
use serde::Serialize;
use sp_core::keccak_256;
use sp_core::{ecdsa, Pair};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::protocols::{DefaultCryptoHasher, DefaultSecurityLevel};
use gadget_common::channels::PublicKeyGossipMessage;

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::DfnsKeygenProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<DfnsCGGMP21KeygenExtraParams, gadget_common::Error> {
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

    let i = p1_job
        .participants
        .0
        .iter()
        .position(|p| p.0 == config.account_id.0)
        .expect("Should exist") as u16;

    let params = DfnsCGGMP21KeygenExtraParams {
        i,
        t: threshold as u16,
        n: participants.len() as u16,
        role_type,
        job_id,
        user_id_to_account_id_mapping,
    };

    Ok(params)
}

#[derive(Clone)]
pub struct DfnsCGGMP21KeygenExtraParams {
    i: u16,
    t: u16,
    n: u16,
    job_id: u64,
    role_type: roles::RoleType,
    user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn run_and_serialize_keygen<
    'r,
    E: Curve,
    S: SecurityLevel,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
    D,
    R,
>(
    tracer: &mut PerfProfiler,
    eid: dfns_cggmp21::ExecutionId<'r>,
    i: u16,
    n: u16,
    t: u16,
    party: MpcParty<Msg<E, S, H>, D>,
    mut rng: R,
) -> Result<Vec<u8>, JobError>
where
    D: Delivery<Msg<E, S, H>>,
    R: RngCore + CryptoRng,
{
    let builder = KeygenBuilder::<E, S, H>::new(eid, i, n);
    let incomplete_key_share = builder
        .set_progress_tracer(tracer)
        .set_threshold(t)
        .start(&mut rng, party)
        .await
        .map_err(|err| JobError {
            reason: format!("Keygen protocol error (run_and_serialize_keygen): {err:?}"),
        })?;
    serialize(&incomplete_key_share).map_err(|err| JobError {
        reason: format!("Keygen protocol error (run_and_serialize_keygen - serde): {err:?}"),
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_and_serialize_keyrefresh<
    'r,
    E: Curve,
    S: SecurityLevel,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
    D,
>(
    logger: &DebugLogger,
    incomplete_key_share: Vec<u8>,
    pregenerated_primes: PregeneratedPrimes<S>,
    tracer: &mut PerfProfiler,
    aux_eid: dfns_cggmp21::ExecutionId<'r>,
    i: u16,
    n: u16,
    party: MpcParty<aux_only::Msg<H, S>, D>,
    mut rng: StdRng,
) -> Result<(Vec<u8>, Vec<u8>), JobError>
where
    D: Delivery<aux_only::Msg<H, S>>,
{
    let incomplete_key_share: dfns_cggmp21::key_share::Valid<
        dfns_cggmp21::key_share::DirtyIncompleteKeyShare<E>,
    > = deserialize(&incomplete_key_share).map_err(|err| JobError {
        reason: format!("Keygen protocol error (run_and_serialize_keyrefresh): {err:?}"),
    })?;

    let aux_info_builder =
        AuxInfoGenerationBuilder::<S, H>::new_aux_gen(aux_eid, i, n, pregenerated_primes);

    let aux_info = aux_info_builder
        .set_progress_tracer(tracer)
        .start(&mut rng, party)
        .await
        .map_err(|err| JobError {
            reason: format!("Aux info protocol error: {err:?}"),
        })?;
    let perf_report = tracer.get_report().map_err(|err| JobError {
        reason: format!("Aux info protocol error: {err:?}"),
    })?;
    logger.trace(format!("Aux info protocol report: {perf_report}"));
    logger.debug("Finished AsyncProtocol - Aux Info");

    let key_share: KeyShare<E, S> = DirtyKeyShare {
        core: incomplete_key_share.into_inner(),
        aux: aux_info.into_inner(),
    }
    .validate()
    .map_err(|err| JobError {
        reason: format!("Keygen protocol validation error: {err:?}"),
    })?;

    // let key_share =
    //     dfns_cggmp21::KeyShare::<E, S>::make(incomplete_key_share, aux_info).map_err(|err| {
    //         JobError {
    //             reason: format!("Key share error: {err:?}"),
    //         }
    //     })?;
    // Serialize the key share and the public key
    serialize(&key_share)
        .map(|ks| (ks, key_share.shared_public_key.to_bytes(true).to_vec()))
        .map_err(|err| JobError {
            reason: format!("Keygen protocol error (run_and_serialize_keyrefresh): {err:?}"),
        })
}

pub type CreatePartyResult<M> = (
    UnboundedSender<PublicKeyGossipMessage>,
    futures::channel::mpsc::UnboundedReceiver<PublicKeyGossipMessage>,
    MpcParty<
        M,
        (
            futures::channel::mpsc::UnboundedReceiver<Result<Incoming<M>, TryRecvError>>,
            UnboundedSender<Outgoing<M>>,
        ),
    >,
);

#[allow(clippy::too_many_arguments)]
pub fn create_party<E: Curve, N: Network, L: SecurityLevel, M>(
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    mapping: Arc<HashMap<UserID, ecdsa::Public>>,
    id: ecdsa::Public,
    network: N,
    logger: DebugLogger,
    i: u16,
) -> CreatePartyResult<M>
where
    N: Network,
    L: SecurityLevel,
    E: Curve,
    M: Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
{
    let (tx_to_outbound, rx_async_proto, broadcast_tx_to_outbound, broadcast_rx_from_gadget) =
        gadget_common::channels::create_job_manager_to_async_protocol_channel_split_io::<
            _,
            PublicKeyGossipMessage,
            Outgoing<M>,
            Incoming<M>,
        >(
            protocol_message_channel,
            associated_block_id,
            associated_retry_id,
            associated_session_id,
            associated_task_id,
            mapping,
            id,
            network,
            logger,
            i,
        );
    let delivery = (rx_async_proto, tx_to_outbound);
    (
        broadcast_tx_to_outbound,
        broadcast_rx_from_gadget,
        MpcParty::connected(delivery),
    )
}

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::DfnsKeygenProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: DfnsCGGMP21KeygenExtraParams,
) -> Result<BuiltExecutableJobWrapper, JobError> {
    let key_store = config.key_store.clone();
    let key_store2 = config.key_store.clone();
    let protocol_output = Arc::new(tokio::sync::Mutex::new(None));
    let protocol_output_clone = protocol_output.clone();
    let client = config.get_jobs_client();
    let my_role_id = key_store.pair().public();
    let logger = config.logger.clone();
    let network = config.clone();

    let (i, t, n, role_type, mapping) = (
        additional_params.i,
        additional_params.t,
        additional_params.n,
        additional_params.role_type.clone(),
        additional_params.user_id_to_account_id_mapping,
    );

    Ok(JobBuilder::new()
        .protocol(async move {
            let rng = rand::rngs::StdRng::from_entropy();
            logger.info(format!(
                "Starting Keygen Protocol with params: i={i}, t={t}, n={n}"
            ));

            let job_id_bytes = additional_params.job_id.to_be_bytes();
            let mix = keccak_256(b"dnfs-cggmp21-keygen");
            let eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
            let eid = dfns_cggmp21::ExecutionId::new(&eid_bytes);
            let mix = keccak_256(b"dnfs-cggmp21-keygen-aux");
            let aux_eid_bytes = [&job_id_bytes[..], &mix[..]].concat();
            let aux_eid = dfns_cggmp21::ExecutionId::new(&aux_eid_bytes);
            let tracer = PerfProfiler::new();

            let (key_share, serialized_public_key, tx2, rx2) =
                match role_type {
                    roles::RoleType::Tss(
                        roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                    ) => {
                        run_full_keygen_protocol::<
                            Secp256k1,
                            DefaultSecurityLevel,
                            DefaultCryptoHasher,
                            _,
                            _,
                        >(
                            protocol_message_channel,
                            associated_block_id,
                            associated_retry_id,
                            associated_session_id,
                            associated_task_id,
                            mapping.clone(),
                            my_role_id,
                            network.clone(),
                            tracer,
                            eid,
                            aux_eid,
                            i,
                            n,
                            t,
                            rng,
                            &logger,
                            &job_id_bytes,
                            &key_store,
                            role_type.clone(),
                        )
                        .await?
                    }
                    roles::RoleType::Tss(
                        roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1,
                    ) => {
                        run_full_keygen_protocol::<
                            Secp256r1,
                            DefaultSecurityLevel,
                            DefaultCryptoHasher,
                            _,
                            _,
                        >(
                            protocol_message_channel,
                            associated_block_id,
                            associated_retry_id,
                            associated_session_id,
                            associated_task_id,
                            mapping.clone(),
                            my_role_id,
                            network.clone(),
                            tracer,
                            eid,
                            aux_eid,
                            i,
                            n,
                            t,
                            rng,
                            &logger,
                            &job_id_bytes,
                            &key_store,
                            role_type.clone(),
                        )
                        .await?
                    }
                    roles::RoleType::Tss(
                        roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark,
                    ) => {
                        run_full_keygen_protocol::<
                            Stark,
                            DefaultSecurityLevel,
                            DefaultCryptoHasher,
                            _,
                            _,
                        >(
                            protocol_message_channel,
                            associated_block_id,
                            associated_retry_id,
                            associated_session_id,
                            associated_task_id,
                            mapping.clone(),
                            my_role_id,
                            network.clone(),
                            tracer,
                            eid,
                            aux_eid,
                            i,
                            n,
                            t,
                            rng,
                            &logger,
                            &job_id_bytes,
                            &key_store,
                            role_type.clone(),
                        )
                        .await?
                    }
                    _ => unreachable!("Invalid role type"),
                };

            logger.debug("Finished AsyncProtocol - Keygen");

            let sig_scheme = match role_type {
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                ) => jobs::tss::DigitalSignatureScheme::EcdsaSecp256k1,
                roles::RoleType::Tss(
                    roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256r1,
                ) => jobs::tss::DigitalSignatureScheme::EcdsaSecp256r1,
                roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Stark) => {
                    jobs::tss::DigitalSignatureScheme::EcdsaStark
                }
                _ => unreachable!("Invalid role type"),
            };

            let job_result = handle_public_key_gossip(
                key_store,
                &logger,
                &serialized_public_key,
                sig_scheme,
                t,
                i,
                tx2,
                rx2,
            )
            .await?;
            *protocol_output.lock().await = Some((key_share, job_result));
            Ok(())
        })
        .post(async move {
            // TODO: handle protocol blames
            // Store the keys locally, as well as submitting them to the blockchain
            if let Some((key_share, job_result)) = protocol_output_clone.lock().await.take() {
                key_store2
                    .set_job_result(additional_params.job_id, key_share)
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
pub async fn handle_public_key_gossip<KBE: KeystoreBackend>(
    key_store: ECDSAKeyStore<KBE>,
    logger: &DebugLogger,
    serialized_public_key: &[u8],
    digital_signature_scheme: jobs::tss::DigitalSignatureScheme,
    t: u16,
    i: u16,
    broadcast_tx_to_outbound: UnboundedSender<PublicKeyGossipMessage>,
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
    let key_hashed = keccak_256(serialized_public_key);
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

    logger.debug(format!("Needs to receive {} signatures", t - 1));

    for _ in 0..(t - 1) {
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
        let maybe_signature = ecdsa::Signature::from_slice(&message.signature);
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
        logger.debug(format!("Received {}/{t} signatures", received_keys.len()));
    }

    // Order and collect the map to ensure symmetric submission to blockchain
    let signatures = received_keys
        .into_iter()
        .sorted_by_key(|x| x.0)
        .map(|r| BoundedVec(r.1))
        .collect::<Vec<_>>();

    let participants = received_participants
        .into_iter()
        .sorted_by_key(|x| x.0)
        .map(|(_, p)| BoundedVec(p.0.to_vec()))
        .collect::<Vec<_>>();

    if signatures.len() < t as usize {
        return Err(JobError {
            reason: format!(
                "Received {} signatures, expected at least {t}",
                signatures.len(),
            ),
        });
    }

    let res = jobs::tss::DKGTSSKeySubmissionResult {
        signature_scheme: digital_signature_scheme,
        key: BoundedVec(serialized_public_key.to_vec()),
        participants: BoundedVec(participants),
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
        known_signers.len() >= data.threshold as usize,
        "NotEnoughSigners"
    );
    logger.debug(format!(
        "Verified {}/{} signatures",
        known_signers.len(),
        data.threshold
    ));
}

async fn handle_post_incomplete_keygen<S: SecurityLevel, KBE: KeystoreBackend>(
    tracer: &PerfProfiler,
    logger: &DebugLogger,
    job_id_bytes: &[u8],
    key_store: &ECDSAKeyStore<KBE>,
) -> Result<(PerfProfiler, PregeneratedPrimes<S>), JobError> {
    let perf_report = tracer.get_report().map_err(|err| JobError {
        reason: format!("Keygen protocol error (handle_post_incomplete_keygen): {err:?}"),
    })?;
    logger.trace(format!("Incomplete Keygen protocol report: {perf_report}"));
    logger.debug("Finished AsyncProtocol - Incomplete Keygen");
    let tracer = PerfProfiler::new();

    let pregenerated_primes_key =
        keccak_256(&[&b"dfns-cggmp21-keygen-primes"[..], job_id_bytes].concat());
    let now = tokio::time::Instant::now();
    let pregenerated_primes = tokio::task::spawn_blocking(|| {
        let mut rng = OsRng;
        dfns_cggmp21::PregeneratedPrimes::<S>::generate(&mut rng)
    })
    .await
    .map_err(|err| JobError {
        reason: format!("Failed to generate pregenerated primes: {err:?}"),
    })?;

    let elapsed = now.elapsed();
    logger.debug(format!("Pregenerated primes took {elapsed:?}"));

    key_store
        .set(&pregenerated_primes_key, pregenerated_primes.clone())
        .await
        .map_err(|err| JobError {
            reason: format!("Failed to store pregenerated primes: {err:?}"),
        })?;
    Ok((tracer, pregenerated_primes))
}

#[allow(clippy::too_many_arguments)]
async fn run_full_keygen_protocol<
    'a,
    E: Curve,
    S: SecurityLevel,
    H: Digest<OutputSize = U32> + Clone + Send + 'static,
    KBE: KeystoreBackend,
    N: Network,
>(
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    mapping: Arc<HashMap<UserID, ecdsa::Public>>,
    my_role_id: ecdsa::Public,
    network: N,
    mut tracer: PerfProfiler,
    eid: dfns_cggmp21::ExecutionId<'a>,
    aux_eid: dfns_cggmp21::ExecutionId<'a>,
    i: u16,
    n: u16,
    t: u16,
    rng: StdRng,
    logger: &DebugLogger,
    job_id_bytes: &[u8],
    key_store: &ECDSAKeyStore<KBE>,
    role_type: roles::RoleType,
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        UnboundedSender<PublicKeyGossipMessage>,
        futures::channel::mpsc::UnboundedReceiver<PublicKeyGossipMessage>,
    ),
    JobError,
> {
    let (tx0, rx0, tx1, rx1, tx2, rx2) =
        gadget_common::channels::create_job_manager_to_async_protocol_channel_split_io_triplex(
            protocol_message_channel,
            associated_block_id,
            associated_retry_id,
            associated_session_id,
            associated_task_id,
            mapping,
            my_role_id,
            network,
            logger.clone(),
        );
    let delivery = (rx0, tx0);
    let party = MpcParty::<Msg<E, S, H>, _, _>::connected(delivery);
    let incomplete_key_share =
        run_and_serialize_keygen::<E, S, H, _, _>(&mut tracer, eid, i, n, t, party, rng.clone())
            .await?;
    let (mut tracer, pregenerated_primes) =
        handle_post_incomplete_keygen::<S, KBE>(&tracer, logger, job_id_bytes, key_store).await?;

    logger.info(format!("Will now run Keygen protocol: {role_type:?}"));

    let delivery = (rx1, tx1);
    let party = MpcParty::<aux_only::Msg<H, S>, _, _>::connected(delivery);
    let (key_share, serialized_public_key) = run_and_serialize_keyrefresh::<E, S, H, _>(
        logger,
        incomplete_key_share,
        pregenerated_primes,
        &mut tracer,
        aux_eid,
        i,
        n,
        party,
        rng,
    )
    .await?;

    Ok((key_share, serialized_public_key, tx2, rx2))
}
