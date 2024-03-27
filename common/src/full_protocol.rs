use crate::client::{ClientWithApi, JobsClient, PalletSubmitter};
use crate::config::{DebugLogger, GadgetProtocol, Network, NetworkAndProtocolSetup};
use crate::gadget::message::GadgetProtocolMessage;
use crate::gadget::work_manager::WorkManager;
use crate::gadget::{JobInitMetadata, WorkManagerConfig};
use crate::keystore::{ECDSAKeyStore, KeystoreBackend};
use crate::prometheus::PrometheusConfig;
use crate::protocol::AsyncProtocol;
use crate::tangle_runtime::*;
use crate::Error;
use async_trait::async_trait;
use gadget_core::job::{BuiltExecutableJobWrapper, JobError};
use gadget_core::job_manager::{ProtocolWorkManager, WorkManagerInterface};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sp_core::ecdsa::{Public, Signature};
use sp_core::{keccak_256, sr25519};
use sp_io::crypto::ecdsa_verify_prehashed;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

pub type SharedOptional<T> = Arc<Mutex<Option<T>>>;

#[async_trait]
pub trait FullProtocolConfig: Clone + Send + Sync + Sized + 'static {
    type AsyncProtocolParameters: Send + Sync + Clone;
    type Client: ClientWithApi;
    type Network: Network;
    type AdditionalNodeParameters: Clone + Send + Sync + 'static;
    type KeystoreBackend: KeystoreBackend;
    async fn new(
        client: Self::Client,
        pallet_tx: Arc<dyn PalletSubmitter>,
        network: Self::Network,
        logger: DebugLogger,
        account_id: sr25519::Public,
        key_store: ECDSAKeyStore<Self::KeystoreBackend>,
        prometheus_config: PrometheusConfig,
    ) -> Result<Self, Error>;
    async fn generate_protocol_from(
        &self,
        associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
        associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
        associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
        associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
        protocol_message_rx: UnboundedReceiver<GadgetProtocolMessage>,
        additional_params: Self::AsyncProtocolParameters,
    ) -> Result<BuiltExecutableJobWrapper, JobError>;

    /// This function returns the internally-used network for the protocol.
    ///
    /// Important: This function should never be used directly, it is for internal use only.
    /// Instead, `Self` implements `Network` and should instead be used for networking, as it
    /// grants metrics and message signing and verification to messages
    fn internal_network(&self) -> &Self::Network;
    /// Given an input of metadata for a job, return a set of parameters that can be used to
    /// construct a protocol.
    ///
    /// The provided work manager should only be used for querying recorded_messages
    async fn create_next_job(
        &self,
        job: JobInitMetadata,
        work_manager: &ProtocolWorkManager<WorkManager>,
    ) -> Result<Self::AsyncProtocolParameters, Error>;

    async fn process_error(&self, error: Error, _job_manager: &ProtocolWorkManager<WorkManager>) {
        self.logger().error(format!("Error in protocol: {error}"));
    }

    fn account_id(&self) -> &sr25519::Public;

    fn name(&self) -> String;

    fn role_filter(&self, role: roles::RoleType) -> bool;

    fn phase_filter(
        &self,
        job: jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    ) -> bool;

    fn jobs_client(&self) -> &SharedOptional<JobsClient<Self::Client>>;
    fn pallet_tx(&self) -> Arc<dyn PalletSubmitter>;

    fn logger(&self) -> DebugLogger;

    fn client(&self) -> Self::Client;
    fn get_jobs_client(&self) -> JobsClient<Self::Client> {
        self.jobs_client()
            .lock()
            .clone()
            .expect("Jobs client not initialized")
    }
    fn key_store(&self) -> &ECDSAKeyStore<Self::KeystoreBackend>;
    fn get_work_manager_config(&self) -> WorkManagerConfig {
        Default::default()
    }
}

#[async_trait]
impl<T: FullProtocolConfig> AsyncProtocol for T {
    type AdditionalParams = T::AsyncProtocolParameters;

    async fn generate_protocol_from(
        &self,
        associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
        associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
        associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
        associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
        protocol_message_rx: UnboundedReceiver<GadgetProtocolMessage>,
        additional_params: Self::AdditionalParams,
    ) -> Result<BuiltExecutableJobWrapper, JobError> {
        T::generate_protocol_from(
            self,
            associated_block_id,
            associated_retry_id,
            associated_session_id,
            associated_task_id,
            protocol_message_rx,
            additional_params,
        )
        .await
    }
}

#[async_trait]
impl<T: FullProtocolConfig> NetworkAndProtocolSetup for T {
    type Network = T;
    type Protocol = T;
    type Client = T::Client;

    async fn build_network_and_protocol(
        &self,
        jobs_client: JobsClient<Self::Client>,
    ) -> Result<(Self::Network, Self::Protocol), Error> {
        let jobs_client_store = T::jobs_client(self);
        jobs_client_store.lock().replace(jobs_client);
        Ok((self.clone(), self.clone()))
    }

    fn pallet_tx(&self) -> Arc<dyn PalletSubmitter> {
        T::pallet_tx(self)
    }

    fn logger(&self) -> DebugLogger {
        T::logger(self)
    }

    fn client(&self) -> Self::Client {
        T::client(self)
    }
}

#[async_trait]
impl<T: FullProtocolConfig> GadgetProtocol<T::Client> for T {
    async fn create_next_job(
        &self,
        job: JobInitMetadata,
        work_manager: &ProtocolWorkManager<WorkManager>,
    ) -> Result<<Self as AsyncProtocol>::AdditionalParams, Error> {
        T::create_next_job(self, job, work_manager).await
    }

    async fn process_error(&self, error: Error, job_manager: &ProtocolWorkManager<WorkManager>) {
        T::process_error(self, error, job_manager).await;
    }

    fn account_id(&self) -> &sr25519::Public {
        T::account_id(self)
    }

    fn name(&self) -> String {
        T::name(self)
    }

    fn role_filter(&self, role: roles::RoleType) -> bool {
        T::role_filter(self, role)
    }

    fn phase_filter(
        &self,
        job: jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    ) -> bool {
        T::phase_filter(self, job)
    }

    fn client(&self) -> JobsClient<T::Client> {
        T::get_jobs_client(self)
    }

    fn logger(&self) -> DebugLogger {
        T::logger(self)
    }

    fn get_work_manager_config(&self) -> WorkManagerConfig {
        T::get_work_manager_config(self)
    }
}

#[async_trait]
impl<T: FullProtocolConfig> Network for T {
    async fn next_message(&self) -> Option<<WorkManager as WorkManagerInterface>::ProtocolMessage> {
        let mut message = T::internal_network(self).next_message().await?;
        if let Some(peer_public_key) = message.from_network_id {
            if let Ok(payload_and_signature) =
                <PayloadAndSignature as Decode>::decode(&mut message.payload.as_slice())
            {
                let hashed_message = keccak_256(&payload_and_signature.payload);
                if ecdsa_verify_prehashed(
                    &payload_and_signature.signature,
                    &hashed_message,
                    &peer_public_key,
                ) {
                    message.payload = payload_and_signature.payload;
                    crate::prometheus::BYTES_RECEIVED.inc_by(message.payload.len() as u64);
                    return Some(message);
                } else {
                    self.logger()
                        .warn("Received a message with an invalid signature.")
                }
            } else {
                self.logger()
                    .warn("Received a message without a valid payload and signature.")
            }
        } else {
            self.logger()
                .warn("Received a message without a valid sender public key.")
        }

        // This message was invalid. Thus, poll the next message
        self.next_message().await
    }

    async fn send_message(
        &self,
        mut message: <WorkManager as WorkManagerInterface>::ProtocolMessage,
    ) -> Result<(), Error> {
        // Sign the hash of the message
        let hashed_message = keccak_256(&message.payload);
        let signature = self.key_store().pair().sign_prehashed(&hashed_message);
        let payload_and_signature = PayloadAndSignature {
            payload: message.payload,
            signature,
        };

        let serialized_message = Encode::encode(&payload_and_signature);
        message.payload = serialized_message;
        crate::prometheus::BYTES_SENT.inc_by(message.payload.len() as u64);
        T::internal_network(self).send_message(message).await
    }

    fn greatest_authority_id(&self) -> Option<Public> {
        T::internal_network(self).greatest_authority_id()
    }
}

/// Used for constructing an instance of a node. If there is both a keygen and a signing protocol, then,
/// the length of the vectors are 2. The length of the vector is equal to the numbers of protocols that
/// the constructed node is going to concurrently execute
pub struct NodeInput<C: ClientWithApi, N: Network, KBE: KeystoreBackend, D> {
    pub clients: Vec<C>,
    pub networks: Vec<N>,
    pub account_id: sr25519::Public,
    pub logger: DebugLogger,
    pub pallet_tx: Arc<dyn PalletSubmitter>,
    pub keystore: ECDSAKeyStore<KBE>,
    pub node_index: usize,
    pub additional_params: D,
    pub prometheus_config: PrometheusConfig,
}

#[derive(Encode, Decode)]
pub struct PayloadAndSignature {
    payload: Vec<u8>,
    signature: Signature,
}
