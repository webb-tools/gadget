use gadget_common::full_protocol::SharedOptional;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use sp_core::sr25519;

#[protocol]
pub struct StubProtocol<C: ClientWithApi, N: Network, KBE: KeystoreBackend> {
    pallet_tx: Arc<dyn PalletSubmitter>,
    logger: DebugLogger,
    client: C,
    network: N,
    account_id: sr25519::Public,
    key_store: ECDSAKeyStore<KBE>,
    prometheus_config: PrometheusConfig,
    jobs_client: Arc<Mutex<Option<JobsClient<C>>>>,
}

#[async_trait]
impl<C: ClientWithApi + 'static, N: Network, KBE: KeystoreBackend> FullProtocolConfig
    for StubProtocol<C, N, KBE>
{
    type AsyncProtocolParameters = ();
    type Client = C;
    type Network = N;
    type AdditionalNodeParameters = ();
    type KeystoreBackend = KBE;

    async fn new(
        client: Self::Client,
        pallet_tx: Arc<dyn PalletSubmitter>,
        network: Self::Network,
        logger: DebugLogger,
        account_id: sr25519::Public,
        key_store: ECDSAKeyStore<Self::KeystoreBackend>,
        prometheus_config: PrometheusConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            pallet_tx,
            logger,
            client,
            network,
            account_id,
            key_store,
            prometheus_config,
            jobs_client: Arc::new(Mutex::new(None)),
        })
    }

    async fn generate_protocol_from(
        &self,
        _associated_block_id: <WorkManager as WorkManagerInterface>::Clock,
        _associated_retry_id: <WorkManager as WorkManagerInterface>::RetryID,
        _associated_session_id: <WorkManager as WorkManagerInterface>::SessionID,
        _associated_task_id: <WorkManager as WorkManagerInterface>::TaskID,
        _protocol_message_rx: UnboundedReceiver<GadgetProtocolMessage>,
        _additional_params: Self::AsyncProtocolParameters,
    ) -> Result<BuiltExecutableJobWrapper, JobError> {
        Ok(JobBuilder::new().protocol(async move { Ok(()) }).build())
    }

    fn internal_network(&self) -> &Self::Network {
        &self.network
    }

    async fn create_next_job(
        &self,
        _job: JobInitMetadata,
        _work_manager: &ProtocolWorkManager<WorkManager>,
    ) -> Result<Self::AsyncProtocolParameters, Error> {
        Ok(())
    }

    fn account_id(&self) -> &sr25519::Public {
        &self.account_id
    }

    fn name(&self) -> String {
        "STUB-PROTOCOL".to_string()
    }

    fn role_filter(&self, _role: roles::RoleType) -> bool {
        false
    }

    fn phase_filter(
        &self,
        _job: jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    ) -> bool {
        false
    }

    fn jobs_client(&self) -> &SharedOptional<JobsClient<Self::Client>> {
        &self.jobs_client
    }

    fn pallet_tx(&self) -> Arc<dyn PalletSubmitter> {
        self.pallet_tx.clone()
    }

    fn logger(&self) -> DebugLogger {
        self.logger.clone()
    }

    fn key_store(&self) -> &ECDSAKeyStore<Self::KeystoreBackend> {
        &self.key_store
    }

    fn client(&self) -> Self::Client {
        self.client.clone()
    }
}

// Generates the main entry point for the crate. The input is variadic, and accepts an arbitrary number of protocol configurations.
// For example, you may supply both a KeygenConfig and a SigningConfig to generate a main entry point that runs both protocols concurrently.
// In the below example, the generated run command will run two duplicated protocols concurrently. In a real example, you would want to supply
// The config type for each protocol you want to run in tandem.
generate_setup_and_run_command!(StubProtocol, StubProtocol);

// An Example usage of generating signing and keygen tests
// Note: since the StubProtocol does not submit any JobResults, the wait_for_job_completion function will not work as expected. This is just an example of how to use the macro.
// test_utils::generate_signing_and_keygen_tss_tests!(
//    2,
//    3,
//    ThresholdSignatureRoleType::GennaroDKGBls381
//);
