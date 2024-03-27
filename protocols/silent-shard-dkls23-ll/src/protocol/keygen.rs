use dfns_cggmp21_protocol::protocols::keygen::handle_public_key_gossip;
use gadget_common::channels;
use gadget_common::client::ClientWithApi;
use gadget_common::config::Network;

use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::gadget::JobInitMetadata;
use gadget_common::keystore::KeystoreBackend;
use gadget_common::prelude::*;
use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::jobs::tss::DigitalSignatureScheme;
use gadget_core::job::{BuiltExecutableJobWrapper, JobBuilder, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use k256::elliptic_curve::group::GroupEncoding;
use rand::SeedableRng;
use round_based_21::{Incoming, Outgoing};

use sp_core::{ecdsa, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::rounds::keygen::{run_threshold_keygen, Msg};

#[derive(Clone)]
pub struct SilentShardDKLS23KeygenExtraParams {
    pub i: u16,
    pub t: u16,
    pub n: u16,
    pub job_id: u64,
    pub role_type: roles::RoleType,
    pub user_id_to_account_id_mapping: Arc<HashMap<UserID, ecdsa::Public>>,
}

pub async fn create_next_job<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentShardDKLS23KeygenProtocol<C, N, KBE>,
    job: JobInitMetadata,
    _work_manager: &ProtocolWorkManager<WorkManager>,
) -> Result<SilentShardDKLS23KeygenExtraParams, gadget_common::Error> {
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

    let params = SilentShardDKLS23KeygenExtraParams {
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

pub async fn generate_protocol_from<KBE: KeystoreBackend, C: ClientWithApi, N: Network>(
    config: &crate::SilentShardDKLS23KeygenProtocol<C, N, KBE>,
    associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
    associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
    associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
    protocol_message_channel: UnboundedReceiver<GadgetProtocolMessage>,
    additional_params: SilentShardDKLS23KeygenExtraParams,
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

    let _role = match role_type {
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
            let key_share = run_threshold_keygen(Some(&mut tracer), i, t, n, &mut rng, party)
                .await
                .map_err(|e| JobError {
                    reason: format!("Keygen protocol error: {e:?}"),
                })?;
            let perf_report = tracer.get_report().map_err(|err| JobError {
                reason: format!("Keygen protocol error: {err:?}"),
            })?;
            logger.trace(format!("Incomplete Keygen protocol report: {perf_report}"));
            logger.debug("Finished AsyncProtocol - Incomplete Keygen");

            let job_result = handle_public_key_gossip(
                key_store2,
                &logger,
                &key_share.verifying_key.to_bytes(),
                DigitalSignatureScheme::EcdsaSecp256k1,
                t,
                i,
                broadcast_tx_to_outbound,
                broadcast_rx_from_gadget,
            )
            .await?;

            *protocol_output.lock().await = Some((key_share, job_result));
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
