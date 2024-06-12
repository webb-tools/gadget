// use gadget_common::prelude::GadgetEnvironment;

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolValue;
use avs::IncredibleSquaringTaskManager::TaskResponse;

pub mod aggregator;
pub mod avs;
pub mod challenger;
pub mod operator;
pub mod rpc_client;

pub fn get_task_response_digest(task_response: &TaskResponse) -> B256 {
    let encoded = task_response.abi_encode_packed();
    keccak256(encoded)
}

// #[derive(Default)]
// pub struct EigenEnvironment;

// impl GadgetEnvironment for EigenEnvironment {
//     type Event = EigenEvent;
//     type ProtocolMessage = EigenProtocolMessage;
//     type Client = EigenRuntime;
//     type WorkManager = EigenWorkManager;
//     type Error = crate::Error;
//     type Clock = <Self::WorkManager as WorkManagerInterface>::Clock;
//     type RetryID = <Self::WorkManager as WorkManagerInterface>::RetryID;
//     type TaskID = <Self::WorkManager as WorkManagerInterface>::TaskID;
//     type SessionID = <Self::WorkManager as WorkManagerInterface>::SessionID;
//     type TransactionManager = TangleTransactionManager;

//     fn build_protocol_message<Payload: Serialize>(
//         associated_block_id: Self::Clock,
//         associated_session_id: Self::SessionID,
//         associated_retry_id: Self::RetryID,
//         associated_task_id: Self::TaskID,
//         from: UserID,
//         to: Option<UserID>,
//         payload: &Payload,
//         from_account_id: Option<ecdsa::Public>,
//         to_network_id: Option<ecdsa::Public>,
//     ) -> Self::ProtocolMessage {
//         EigenProtocolMessage {
//             associated_block_id,
//             associated_session_id,
//             associated_retry_id,
//             task_hash: associated_task_id,
//             from,
//             to,
//             payload: serialize(payload).expect("Failed to serialize message"),
//             from_network_id: from_account_id,
//             to_network_id,
//         }
//     }
// }

// pub enum EventType {
//     BlsApkRegistry(BlsApkRegistry::BlsApkRegistryEvents),
//     RegistryCoordinator(RegistryCoordinator::RegistryCoordinatorEvents),
// }
// pub struct EigenEvent<T> {
//     pub event: T,
//     number: <EigenEnvironment as GadgetEnvironment>::Clock,
// }

// impl EigenEvent<T> {
//     pub fn new(event: T, number: <EigenEnvironment as GadgetEnvironment>::Clock) -> Self {
//         Self { event, number }
//     }
// }

// impl EventMetadata<EigenEnvironment> for EigenEvent {
//     fn number(&self) -> <EigenEnvironment as GadgetEnvironment>::Clock {
//         self.number
//     }
// }
