// This file is part of Tangle.
// Copyright (C) 2022-2023 Webb Technologies Inc.
//
// Tangle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Tangle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Tangle.  If not, see <http://www.gnu.org/licenses/>.

use async_trait::async_trait;
use frame_support::pallet_prelude::*;
use frame_support::traits::Hooks;
use frame_support::{
    construct_runtime, parameter_types,
    traits::{ConstU128, ConstU32, ConstU64, Everything},
    PalletId,
};
use frame_system::EnsureSigned;
use pallet_jobs_rpc_runtime_api::BlockNumberOf;
use sc_client_api::{FinalityNotification, FinalizeSummary};
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use serde::{Deserialize, Serialize};
use sp_api::{ApiRef, ProvideRuntimeApi};
use sp_core::{sr25519, ByteArray, Pair, H256};
use sp_runtime::RuntimeDebug;
use sp_runtime::{traits::Block as BlockT, traits::IdentityLookup, BuildStorage, DispatchResult};
use std::collections::HashMap;
use std::time::Duration;
use tangle_primitives::AccountId;

pub type Balance = u128;
pub type BlockNumber = u64;

pub use crate::mock::mock_wrapper_client::{MockClient, TestExternalitiesPalletSubmitter};
use crate::sync::substrate_test_channel::MultiThreadedTestExternalities;
use gadget_common::debug_logger::DebugLogger;
use gadget_common::full_protocol::NodeInput;
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WorkManager;
use gadget_common::keystore::{ECDSAKeyStore, InMemoryBackend};
use gadget_common::locks::TokioMutexExt;
use gadget_common::prelude::PrometheusConfig;
use gadget_common::Error;
use gadget_core::job_manager::{SendFuture, WorkManagerInterface};
use sp_core::ecdsa;
use sp_keystore::{testing::MemoryKeystore, KeystoreExt, KeystorePtr};
use sp_std::sync::Arc;
use tangle_primitives::jobs::traits::{JobToFee, MPCHandler};
use tangle_primitives::jobs::{
    JobId, JobResult, JobSubmission, JobType, JobWithResult, PhaseResult, ReportRestakerOffence,
    RpcResponseJobsData, ValidatorOffenceType,
};
use tangle_primitives::misbehavior::{MisbehaviorHandler, MisbehaviorSubmission};
use tangle_primitives::roles::traits::RolesHandler;
use tangle_primitives::roles::RoleType;
use tangle_primitives::verifier::{
    arkworks::ArkworksVerifierGroth16Bn254, circom::CircomVerifierGroth16Bn254,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Key type for DKG keys
pub const KEY_TYPE: sp_application_crypto::KeyTypeId = sp_application_crypto::KeyTypeId(*b"role");

pub type Block = frame_system::mocking::MockBlock<Runtime>;

impl frame_system::Config for Runtime {
    type RuntimeOrigin = RuntimeOrigin;
    type Nonce = u64;
    type RuntimeCall = RuntimeCall;
    type Hash = H256;
    type Hashing = sp_runtime::traits::BlakeTwo256;
    type AccountId = AccountId;
    type Block = Block;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type BlockWeights = ();
    type BlockLength = ();
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type DbWeight = ();
    type BaseCallFilter = Everything;
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type RuntimeTask = ();
    type MaxConsumers = ConstU32<16>;
}

impl pallet_balances::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<1>;
    type AccountStore = System;
    type ReserveIdentifier = ();
    type RuntimeHoldReason = RuntimeHoldReason;
    type FreezeIdentifier = ();
    type MaxLocks = ();
    type MaxReserves = ConstU32<50>;
    type MaxFreezes = ();
    type RuntimeFreezeReason = ();
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = ();
    type WeightInfo = ();
}

pub struct JobToFeeHandler;

impl JobToFee<AccountId, BlockNumber, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>
    for JobToFeeHandler
{
    type Balance = Balance;

    fn job_to_fee(
        job: &JobSubmission<
            AccountId,
            BlockNumber,
            MaxParticipants,
            MaxSubmissionLen,
            MaxAdditionalParamsLen,
        >,
    ) -> Balance {
        match job.job_type {
            JobType::DKGTSSPhaseOne(_)
            | JobType::DKGTSSPhaseTwo(_)
            | JobType::DKGTSSPhaseThree(_)
            | JobType::DKGTSSPhaseFour(_) => Dkg::job_to_fee(job),
            JobType::ZkSaaSPhaseOne(_) | JobType::ZkSaaSPhaseTwo(_) => ZkSaaS::job_to_fee(job),
        }
    }

    fn calculate_result_extension_fee(_result: Vec<u8>, _extension_time: BlockNumber) -> Balance {
        20
    }
}

pub struct MockRolesHandler;

impl RolesHandler<AccountId> for MockRolesHandler {
    type Balance = Balance;
    fn record_job_by_validators(_: Vec<AccountId>) -> DispatchResult {
        Ok(())
    }

    fn get_max_active_service_for_restaker(_: AccountId) -> std::option::Option<u32> {
        Some(u32::MAX)
    }
    fn report_offence(_offence_report: ReportRestakerOffence<AccountId>) -> DispatchResult {
        Ok(())
    }

    fn is_restaker(address: AccountId) -> bool {
        let restakers = (0..8)
            .map(id_to_sr25519_public)
            .map(Into::into)
            .collect::<Vec<_>>();
        restakers.contains(&address)
    }

    fn is_restaker_with_role(address: AccountId, _role: RoleType) -> bool {
        let restakers = (0..8)
            .map(id_to_sr25519_public)
            .map(Into::into)
            .collect::<Vec<_>>();
        restakers.contains(&address)
    }

    fn get_validator_role_key(address: AccountId) -> Option<Vec<u8>> {
        let validators = (0..8).map(id_to_ecdsa_pair).collect::<Vec<_>>();
        let restakers = (0..8)
            .map(id_to_sr25519_public)
            .map(AccountId::from)
            .collect::<Vec<_>>();
        let idx = restakers.iter().position(|p| p == &address);
        idx.map(|i| validators[i].public().to_raw_vec())
    }
}

pub struct MockMPCHandler;

impl
    MPCHandler<
        AccountId,
        BlockNumber,
        Balance,
        MaxParticipants,
        MaxSubmissionLen,
        MaxKeyLen,
        MaxDataLen,
        MaxSignatureLen,
        MaxProofLen,
        MaxAdditionalParamsLen,
    > for MockMPCHandler
{
    fn verify(
        data: JobWithResult<
            AccountId,
            MaxParticipants,
            MaxSubmissionLen,
            MaxKeyLen,
            MaxDataLen,
            MaxSignatureLen,
            MaxProofLen,
            MaxAdditionalParamsLen,
        >,
    ) -> DispatchResult {
        match data.result {
            JobResult::DKGPhaseOne(_)
            | JobResult::DKGPhaseTwo(_)
            | JobResult::DKGPhaseThree(_)
            | JobResult::DKGPhaseFour(_) => Dkg::verify(data.result),
            JobResult::ZkSaaSPhaseOne(_) | JobResult::ZkSaaSPhaseTwo(_) => ZkSaaS::verify(data),
        }
    }

    fn verify_validator_report(
        _validator: AccountId,
        _offence: ValidatorOffenceType,
        _signatures: Vec<Vec<u8>>,
    ) -> DispatchResult {
        Ok(())
    }

    fn validate_authority_key(_validator: AccountId, _authority_key: Vec<u8>) -> DispatchResult {
        Ok(())
    }
}

parameter_types! {
    pub const JobsPalletId: PalletId = PalletId(*b"py/jobss");
}

const KB: u32 = 1024;
const MB: u32 = 1024 * KB;

parameter_types! {
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxSubmissionLen: u32 = 64 * MB;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxParticipants: u32 = 10;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxKeyLen: u32 = 256;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxDataLen: u32 = 256;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxSignatureLen: u32 = 256;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxProofLen: u32 = 256;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxActiveJobsPerValidator: u32 = 100;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxRolesPerValidator: u32 = 100;
    #[derive(Clone, RuntimeDebug, Eq, PartialEq, TypeInfo, Encode, Decode)]
    #[derive(Serialize, Deserialize)]
    pub const MaxAdditionalParamsLen: u32 = 256;
}

impl pallet_jobs::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type JobToFee = JobToFeeHandler;
    type RolesHandler = MockRolesHandler;
    type MPCHandler = MockMPCHandler;
    type ForceOrigin = EnsureSigned<AccountId>;
    type MaxParticipants = MaxParticipants;
    type MaxSubmissionLen = MaxSubmissionLen;
    type MaxSignatureLen = MaxSignatureLen;
    type MaxDataLen = MaxDataLen;
    type MaxKeyLen = MaxKeyLen;
    type MaxProofLen = MaxProofLen;
    type MaxActiveJobsPerValidator = MaxActiveJobsPerValidator;
    type MaxAdditionalParamsLen = MaxAdditionalParamsLen;
    type PalletId = JobsPalletId;
    type MisbehaviorHandler = MockMisbehaviorHandler;
    type WeightInfo = ();
}

pub struct MockMisbehaviorHandler;

impl MisbehaviorHandler for MockMisbehaviorHandler {
    fn verify(_data: MisbehaviorSubmission) -> DispatchResult {
        Ok(())
    }
}

impl pallet_dkg::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type UpdateOrigin = EnsureSigned<AccountId>;
    type MaxParticipants = MaxParticipants;
    type MaxSubmissionLen = MaxSubmissionLen;
    type MaxSignatureLen = MaxSignatureLen;
    type MaxDataLen = MaxDataLen;
    type MaxKeyLen = MaxKeyLen;
    type MaxProofLen = MaxProofLen;
    type MaxAdditionalParamsLen = MaxAdditionalParamsLen;
    type WeightInfo = ();
}

impl pallet_zksaas::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;

    type UpdateOrigin = EnsureSigned<AccountId>;
    type Verifier = (ArkworksVerifierGroth16Bn254, CircomVerifierGroth16Bn254);
    type MaxParticipants = MaxParticipants;
    type MaxSubmissionLen = MaxSubmissionLen;
    type MaxSignatureLen = MaxSignatureLen;
    type MaxDataLen = MaxDataLen;
    type MaxKeyLen = MaxKeyLen;
    type MaxProofLen = MaxProofLen;
    type MaxAdditionalParamsLen = MaxAdditionalParamsLen;
    type WeightInfo = ();
}

construct_runtime!(
    pub enum Runtime
    {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        Jobs: pallet_jobs,
        Dkg: pallet_dkg,
        ZkSaaS: pallet_zksaas,
    }
);

sp_api::mock_impl_runtime_apis! {
    impl pallet_jobs_rpc_runtime_api::JobsApi<Block, AccountId, MaxParticipants, MaxSubmissionLen, MaxKeyLen, MaxDataLen, MaxSignatureLen, MaxProofLen, MaxAdditionalParamsLen> for Runtime {
        fn query_jobs_by_validator(&self, validator: AccountId) -> Option<Vec<RpcResponseJobsData<AccountId, BlockNumberOf<Block>, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>>> {
            TEST_EXTERNALITIES.lock().as_ref().unwrap().execute_with(move || {
                Jobs::query_jobs_by_validator(validator)
            })
        }

        fn query_job_by_id(role_type: RoleType, job_id: JobId) -> Option<RpcResponseJobsData<AccountId, BlockNumberOf<Block>, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>> {
            TEST_EXTERNALITIES.lock().as_ref().unwrap().execute_with(move || {
                Jobs::query_job_by_id(role_type, job_id)
            })
        }

        fn query_job_result(role_type: RoleType, job_id: JobId) -> Option<PhaseResult<AccountId, BlockNumberOf<Block>, MaxParticipants, MaxKeyLen, MaxDataLen, MaxSignatureLen, MaxSubmissionLen, MaxProofLen, MaxAdditionalParamsLen>> {
            TEST_EXTERNALITIES.lock().as_ref().unwrap().execute_with(move || {
                Jobs::query_job_result(role_type, job_id)
            })
        }

        fn query_next_job_id() -> JobId {
            TEST_EXTERNALITIES.lock().as_ref().unwrap().execute_with(move || {
                Jobs::query_next_job_id()
            })
        }

        fn query_restaker_role_key(address: AccountId) -> Option<Vec<u8>> {
            TEST_EXTERNALITIES.lock().as_ref().unwrap().execute_with(move || {
                MockRolesHandler::get_validator_role_key(address)
            })
        }
    }
}

pub struct ExtBuilder;

impl Default for ExtBuilder {
    fn default() -> Self {
        ExtBuilder
    }
}

impl ProvideRuntimeApi<Block> for Runtime {
    type Api = Self;
    fn runtime_api(&self) -> ApiRef<Self::Api> {
        ApiRef::from(*self)
    }
}

pub fn id_to_ecdsa_pair(id: u8) -> ecdsa::Pair {
    ecdsa::Pair::from_string(&format!("//Alice///{id}"), None).expect("static values are valid")
}

pub fn id_to_sr25519_pair(id: u8) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//Alice///{id}"), None).expect("static values are valid")
}

pub fn id_to_public(id: u8) -> ecdsa::Public {
    id_to_ecdsa_pair(id).public()
}

pub fn id_to_sr25519_public(id: u8) -> sr25519::Public {
    id_to_sr25519_pair(id).public()
}

sp_externalities::decl_extension! {
    pub struct TracingUnboundedReceiverExt(TracingUnboundedReceiver<<Block as BlockT>::Hash>);
}

#[derive(Clone)]
pub struct MockNetwork {
    peers_tx: Arc<
        HashMap<
            ecdsa::Public,
            UnboundedSender<<WorkManager as WorkManagerInterface>::ProtocolMessage>,
        >,
    >,
    peers_rx: Arc<
        HashMap<
            ecdsa::Public,
            tokio::sync::Mutex<
                UnboundedReceiver<<WorkManager as WorkManagerInterface>::ProtocolMessage>,
            >,
        >,
    >,
    my_id: ecdsa::Public,
}

impl MockNetwork {
    pub fn setup(ids: &Vec<ecdsa::Public>) -> Vec<Self> {
        let mut peers_tx = HashMap::new();
        let mut peers_rx = HashMap::new();
        let mut networks = Vec::new();

        for id in ids {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            peers_tx.insert(*id, tx);
            peers_rx.insert(*id, tokio::sync::Mutex::new(rx));
        }

        let peers_tx = Arc::new(peers_tx);
        let peers_rx = Arc::new(peers_rx);

        for id in ids {
            let network = Self {
                peers_tx: peers_tx.clone(),
                peers_rx: peers_rx.clone(),
                my_id: *id,
            };
            networks.push(network);
        }

        networks
    }
}

#[async_trait]
impl Network for MockNetwork {
    async fn next_message(&self) -> Option<<WorkManager as WorkManagerInterface>::ProtocolMessage> {
        self.peers_rx
            .get(&self.my_id)?
            .lock_timeout(Duration::from_millis(500))
            .await
            .recv()
            .await
    }

    async fn send_message(
        &self,
        message: <WorkManager as WorkManagerInterface>::ProtocolMessage,
    ) -> Result<(), Error> {
        let _check_message_has_ids = message.from_network_id.ok_or(Error::MissingNetworkId)?;
        if let Some(peer_id) = message.to_network_id {
            let tx = self
                .peers_tx
                .get(&peer_id)
                .ok_or(Error::PeerNotFound { id: peer_id })?;
            tx.send(message).map_err(|err| Error::NetworkError {
                err: err.to_string(),
            })?;
        } else {
            // Broadcast to everyone except ourself
            for (peer_id, tx) in self.peers_tx.iter() {
                if peer_id != &self.my_id {
                    tx.send(message.clone())
                        .map_err(|err| Error::NetworkError {
                            err: err.to_string(),
                        })?;
                }
            }
        }
        Ok(())
    }
}

pub type MockBackend = sc_client_api::in_mem::Backend<Block>;

static TEST_EXTERNALITIES: parking_lot::Mutex<Option<MultiThreadedTestExternalities>> =
    parking_lot::Mutex::new(None);

pub fn advance_to_block(block_number: u64) {
    while System::block_number() < block_number {
        System::on_finalize(System::block_number());
        Jobs::on_finalize(System::block_number());
        Balances::on_finalize(System::block_number());
        System::set_block_number(System::block_number() + 1);
        System::on_initialize(System::block_number());
        Jobs::on_initialize(System::block_number());
        Balances::on_initialize(System::block_number());
    }
}

// Checks events against the latest. A contiguous set of events must be
// provided. They must include the most recent RuntimeEvent, but do not have to include
// every past RuntimeEvent.
pub fn assert_events(mut expected: Vec<RuntimeEvent>) {
    let mut actual: Vec<RuntimeEvent> = System::events().iter().map(|e| e.event.clone()).collect();

    expected.reverse();
    for evt in expected {
        let next = actual.pop().expect("RuntimeEvent expected");
        assert_eq!(next, evt, "Events don't match (actual,expected)");
    }
}

/// This function basically just builds a genesis storage key/value store according to
/// our desired mockup.
/// N: number of nodes
/// K: Number of networks accessible per node
/// D: Any data that you want to pass to pass with NodeInput.
/// F: A function that generates a singular full node (all possible protocols) by returning a future representing the node's execution
pub async fn new_test_ext<
    const N: usize,
    const K: usize,
    D: Send + Clone + 'static,
    F: Fn(NodeInput<MockClient<Runtime, Block>, MockNetwork, InMemoryBackend, D>) -> Fut,
    Fut: SendFuture<'static, ()>,
>(
    additional_params: D,
    f: F,
) -> MultiThreadedTestExternalities {
    let mut t = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();

    let role_pairs = (0..N)
        .map(|i| id_to_ecdsa_pair(i as u8))
        .collect::<Vec<_>>();
    let roles_identities = role_pairs
        .iter()
        .map(|pair| pair.public())
        .collect::<Vec<_>>();

    let pairs = (0..N)
        .map(|i| id_to_sr25519_pair(i as u8))
        .collect::<Vec<_>>();
    let account_ids = pairs
        .iter()
        .map(|pair| pair.public().into())
        .collect::<Vec<AccountId>>();

    let balances = account_ids
        .iter()
        .map(|public| (public.clone(), 100u128))
        .collect::<Vec<_>>();

    let networks = (0..K)
        .map(|_| MockNetwork::setup(&roles_identities))
        .collect::<Vec<_>>();

    // Transpose networks
    let networks = (0..N)
        .map(|i| {
            networks
                .iter()
                .map(|network| network[i].clone())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    pallet_balances::GenesisConfig::<Runtime> { balances }
        .assimilate_storage(&mut t)
        .unwrap();

    let mut ext = sp_io::TestExternalities::new(t);
    ext.register_extension(KeystoreExt(Arc::new(MemoryKeystore::new()) as KeystorePtr));

    let ext = MultiThreadedTestExternalities::new(ext);
    assert!(TEST_EXTERNALITIES.lock().replace(ext.clone()).is_none(), "Make sure to run tests serially with -- --test-threads=1 or with nextest to ensure separate program spaces per test");

    let finality_notification_txs = Arc::new(parking_lot::Mutex::new(Vec::<
        TracingUnboundedSender<FinalityNotification<Block>>,
    >::new()));
    let sinks = finality_notification_txs.clone();
    let externalities = ext.clone();

    // Spawn a thread that sends a finality notification whenever it detects a change in block number
    tokio::task::spawn(async move {
        let mut prev: Option<u64> = None;
        loop {
            let number = externalities
                .execute_with_async(move || {
                    let number = System::block_number();
                    System::finalize();
                    advance_to_block(number + 1);
                    number + 1
                })
                .await;
            // log::info!(target: "gadget", "Current block number: {number}");
            if prev.is_none() || prev.unwrap() != number {
                prev = Some(number);
                log::info!(target: "gadget", "Creating finality notification {number}");

                let lock = sinks.lock();
                for sink in lock.iter() {
                    let (faux_sink, faux_stream) = tracing_unbounded("faux_sink", 1024);
                    std::mem::forget(faux_stream);

                    let header = <Block as BlockT>::Header::new_from_number(number);
                    let summary = FinalizeSummary::<Block> {
                        finalized: vec![header.hash()],
                        header,
                        stale_heads: vec![],
                    };

                    let notification = FinalityNotification::from_summary(summary, faux_sink);
                    if sink.unbounded_send(notification).is_err() {
                        log::warn!(target: "gadget", "Will not deliver FinalityNotification because the receiver is gone");
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(12000)).await;
        }
    });

    for (node_index, ((role_pair, pair), networks)) in
        role_pairs.into_iter().zip(pairs).zip(networks).enumerate()
    {
        let mut mock_clients = Vec::new();

        for _ in 0..K {
            mock_clients.push(MockClient::new(Runtime, finality_notification_txs.clone()).await);
        }

        let account_id: AccountId = pair.public().into();

        let logger = DebugLogger {
            peer_id: format!("Peer {node_index}"),
        };

        let pallet_tx = Arc::new(TestExternalitiesPalletSubmitter {
            id: account_id.clone(),
            ext: ext.clone(),
        });

        let keystore = ECDSAKeyStore::in_memory(role_pair);
        let prometheus_config = PrometheusConfig::Disabled;

        let input = NodeInput {
            clients: mock_clients,
            networks,
            account_id: sr25519::Public(account_id.into()),
            logger,
            pallet_tx,
            keystore,
            node_index,
            additional_params: additional_params.clone(),
            prometheus_config,
        };

        let task = f(input);
        tokio::task::spawn(task);
    }

    ext
}

pub mod mock_wrapper_client {
    use crate::mock::RuntimeOrigin;
    use crate::sync::substrate_test_channel::MultiThreadedTestExternalities;
    use async_trait::async_trait;
    use futures::StreamExt;
    use gadget_common::client::{exec_client_function, PalletSubmitter};
    use gadget_common::config::ClientWithApi;
    use gadget_common::locks::TokioMutexExt;
    use gadget_common::tangle_subxt::subxt::utils::AccountId32;
    use gadget_common::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::{
        jobs, roles,
    };
    use gadget_common::tangle_runtime::*;
    use gadget_core::gadget::substrate::{self, Client};
    use pallet_jobs_rpc_runtime_api::JobsApi;
    use parity_scale_codec::{Decode, Encode};
    use sc_client_api::{
        BlockchainEvents, FinalityNotification, FinalityNotifications, ImportNotifications,
        StorageEventStream, StorageKey,
    };
    use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedSender};
    use sp_api::{ApiRef, ProvideRuntimeApi};
    use sp_runtime::traits::Block;
    use sp_runtime::traits::Header;
    use std::sync::Arc;
    use std::time::Duration;
    use tangle_primitives::jobs::JobId;
    use tangle_primitives::AccountId;

    #[derive(Clone)]
    pub struct MockClient<R, B: Block> {
        runtime: Arc<R>,
        finality_notification_stream: Arc<tokio::sync::Mutex<Option<FinalityNotifications<B>>>>,
        latest_finality_notification: Arc<tokio::sync::Mutex<Option<FinalityNotification<B>>>>,
        finality_notification_txs:
            Arc<parking_lot::Mutex<Vec<TracingUnboundedSender<FinalityNotification<B>>>>>,
    }

    impl<R, B: Block> MockClient<R, B> {
        pub async fn new(
            runtime: R,
            finality_notification_txs: Arc<
                parking_lot::Mutex<Vec<TracingUnboundedSender<FinalityNotification<B>>>>,
            >,
        ) -> Self {
            let runtime = Arc::new(runtime);
            let finality_notification_stream = Arc::new(tokio::sync::Mutex::new(None));

            let this = Self {
                runtime,
                finality_notification_stream,
                latest_finality_notification: tokio::sync::Mutex::new(None).into(),
                finality_notification_txs,
            };

            *this
                .finality_notification_stream
                .lock_timeout(Duration::from_millis(500))
                .await = Some(this.finality_notification_stream());
            this
        }
    }

    #[async_trait]
    impl<R: Send + Sync + Clone, B: Block> Client for MockClient<R, B> {
        async fn get_next_finality_notification(&self) -> Option<substrate::FinalityNotification> {
            let mut lock = self
                .finality_notification_stream
                .lock_timeout(Duration::from_millis(500))
                .await;
            let next = lock.as_mut().expect("Should exist").next().await;
            log::trace!(target: "gadget", "Latest Finality Notification: {:?}", next.as_ref().map(|r| r.header.number()));
            *self
                .latest_finality_notification
                .lock_timeout(Duration::from_millis(500))
                .await = next.clone();
            next.map(|n| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(n.header.hash().as_ref());
                let number =
                    Decode::decode(&mut Encode::encode(&n.header.number()).as_slice()).unwrap();
                substrate::FinalityNotification { hash, number }
            })
        }

        async fn get_latest_finality_notification(
            &self,
        ) -> Option<substrate::FinalityNotification> {
            let lock = self
                .latest_finality_notification
                .lock_timeout(Duration::from_millis(500))
                .await;
            if let Some(n) = lock.clone() {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(n.header.hash().as_ref());
                let number =
                    Decode::decode(&mut Encode::encode(&n.header.number()).as_slice()).unwrap();
                Some(substrate::FinalityNotification { hash, number })
            } else {
                drop(lock);
                self.get_next_finality_notification().await
            }
        }
    }

    #[async_trait]
    impl<R: Send + Sync + Clone + 'static, B: Block> ClientWithApi for MockClient<R, B>
    where
        R: ProvideRuntimeApi<B>,
        R::Api: pallet_jobs_rpc_runtime_api::JobsApi<
            B,
            ::tangle_primitives::AccountId,
            super::MaxParticipants,
            super::MaxSubmissionLen,
            super::MaxKeyLen,
            super::MaxDataLen,
            super::MaxSignatureLen,
            super::MaxProofLen,
            super::MaxAdditionalParamsLen,
        >,
    {
        async fn query_jobs_by_validator(
            &self,
            at: [u8; 32],
            validator: AccountId32,
        ) -> Result<
            Option<
                Vec<
                    jobs::RpcResponseJobsData<
                        AccountId32,
                        u64,
                        MaxParticipants,
                        MaxSubmissionLen,
                        MaxAdditionalParamsLen,
                    >,
                >,
            >,
            gadget_common::Error,
        > {
            let at = Decode::decode(&mut Encode::encode(&at).as_slice()).unwrap();
            let validator = tangle_primitives::AccountId::from(validator.0);
            exec_client_function(&self.runtime, move |r| {
                r.runtime_api()
                    .query_jobs_by_validator(at, validator)
                    .map_err(|err| gadget_common::Error::ClientError {
                        err: format!("{err:?}"),
                    })
                    .map(|r| {
                        r.map(|r| {
                            r.into_iter()
                                .flat_map(|r| Decode::decode(&mut Encode::encode(&r).as_slice()))
                                .collect()
                        })
                    })
            })
            .await
        }
        async fn query_job_by_id(
            &self,
            at: [u8; 32],
            role_type: roles::RoleType,
            job_id: u64,
        ) -> Result<
            Option<
                jobs::RpcResponseJobsData<
                    AccountId32,
                    u64,
                    MaxParticipants,
                    MaxSubmissionLen,
                    MaxAdditionalParamsLen,
                >,
            >,
            gadget_common::Error,
        > {
            let at = Decode::decode(&mut Encode::encode(&at).as_slice()).unwrap();
            let role_type = Decode::decode(&mut Encode::encode(&role_type).as_slice()).unwrap();
            exec_client_function(&self.runtime, move |r| {
                r.runtime_api()
                    .query_job_by_id(at, role_type, job_id)
                    .map_err(|err| gadget_common::Error::ClientError {
                        err: format!("{err:?}"),
                    })
                    .map(|r| r.map(|r| Decode::decode(&mut Encode::encode(&r).as_slice()).unwrap()))
            })
            .await
        }

        async fn query_job_result(
            &self,
            at: [u8; 32],
            role_type: roles::RoleType,
            job_id: u64,
        ) -> Result<
            Option<
                jobs::PhaseResult<
                    AccountId32,
                    u64,
                    MaxParticipants,
                    MaxKeyLen,
                    MaxDataLen,
                    MaxSignatureLen,
                    MaxSubmissionLen,
                    MaxProofLen,
                    MaxAdditionalParamsLen,
                >,
            >,
            gadget_common::Error,
        > {
            let at = Decode::decode(&mut Encode::encode(&at).as_slice()).unwrap();
            let role_type = Decode::decode(&mut Encode::encode(&role_type).as_slice()).unwrap();
            exec_client_function(&self.runtime, move |r| {
                r.runtime_api()
                    .query_job_result(at, role_type, job_id)
                    .map_err(|err| gadget_common::Error::ClientError {
                        err: format!("{err:?}"),
                    })
                    .map(|r| r.map(|r| Decode::decode(&mut Encode::encode(&r).as_slice()).unwrap()))
            })
            .await
        }

        async fn query_next_job_id(&self, at: [u8; 32]) -> Result<u64, gadget_common::Error> {
            let at = Decode::decode(&mut Encode::encode(&at).as_slice()).unwrap();
            exec_client_function(&self.runtime, move |r| {
                r.runtime_api().query_next_job_id(at).map_err(|err| {
                    gadget_common::Error::ClientError {
                        err: format!("{err:?}"),
                    }
                })
            })
            .await
        }

        async fn query_restaker_role_key(
            &self,
            at: [u8; 32],
            address: AccountId32,
        ) -> Result<Option<Vec<u8>>, gadget_common::Error> {
            let at = Decode::decode(&mut Encode::encode(&at).as_slice()).unwrap();
            let address = tangle_primitives::AccountId::from(address.0);
            exec_client_function(&self.runtime, move |r| {
                r.runtime_api()
                    .query_restaker_role_key(at, address)
                    .map_err(|err| gadget_common::Error::ClientError {
                        err: format!("{err:?}"),
                    })
                    .map(|r| r.map(|r| r.to_vec()))
            })
            .await
        }

        async fn query_restaker_roles(
            &self,
            _at: [u8; 32],
            _address: AccountId32,
        ) -> Result<Vec<roles::RoleType>, gadget_common::Error> {
            Ok(Default::default())
        }
    }

    impl<R: ProvideRuntimeApi<B>, B: Block> ProvideRuntimeApi<B> for MockClient<R, B> {
        type Api = R::Api;
        fn runtime_api(&self) -> ApiRef<Self::Api> {
            self.runtime.runtime_api()
        }
    }

    impl<R, B: Block> BlockchainEvents<B> for MockClient<R, B> {
        fn import_notification_stream(&self) -> ImportNotifications<B> {
            let (sink, stream) = tracing_unbounded("import_notification_stream", 1024);
            // We are not interested in block import notifications for tests
            std::mem::forget(sink);
            stream
        }

        fn every_import_notification_stream(&self) -> ImportNotifications<B> {
            unimplemented!()
        }

        fn finality_notification_stream(&self) -> FinalityNotifications<B> {
            let (sink, stream) =
                tracing_unbounded::<FinalityNotification<B>>("finality_notification_stream", 1024);
            self.finality_notification_txs.lock().push(sink);
            stream
        }

        fn storage_changes_notification_stream(
            &self,
            _filter_keys: Option<&[StorageKey]>,
            _child_filter_keys: Option<&[(StorageKey, Option<Vec<StorageKey>>)]>,
        ) -> sc_client_api::blockchain::Result<StorageEventStream<<B as Block>::Hash>> {
            unimplemented!()
        }
    }

    pub struct TestExternalitiesPalletSubmitter {
        pub ext: MultiThreadedTestExternalities,
        pub id: AccountId,
    }

    #[async_trait]
    impl PalletSubmitter for TestExternalitiesPalletSubmitter {
        async fn submit_job_result(
            &self,
            role_type: roles::RoleType,
            job_id: JobId,
            result: jobs::JobResult<
                MaxParticipants,
                MaxKeyLen,
                MaxSignatureLen,
                MaxDataLen,
                MaxProofLen,
                MaxAdditionalParamsLen,
            >,
        ) -> Result<(), gadget_common::Error> {
            let id = self.id.clone();
            self.ext
                .execute_with_async(move || {
                    let origin = RuntimeOrigin::signed(id);
                    let res = crate::mock::Jobs::submit_job_result(
                        origin,
                        Decode::decode(&mut Encode::encode(&role_type).as_slice()).unwrap(),
                        job_id,
                        Decode::decode(&mut Encode::encode(&result).as_slice()).unwrap(),
                    );
                    if let Err(err) = res {
                        let err = format!("Pallet tx error: {err:?}");
                        if err.contains("JobNotFound") {
                            // Job has already been submitted (assumption only for tests)
                            Ok(())
                        } else {
                            Err(gadget_common::Error::ClientError { err })
                        }
                    } else {
                        Ok(())
                    }
                })
                .await
        }
    }
}
