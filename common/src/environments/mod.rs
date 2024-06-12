use crate::client::ClientWithApi;
use crate::gadget::message::UserID;
use crate::gadget::tangle::runtime::TangleRuntime;
use crate::gadget::tangle::TangleEvent;
use crate::prelude::{TangleProtocolMessage, TangleWorkManager};
use crate::transaction_manager::tangle::TangleTransactionManager;
use crate::transaction_manager::TransactionManager;
use crate::utils::serialize;
use gadget_core::job_manager::{ProtocolMessageMetadata, WorkManagerInterface};
use serde::Serialize;
use sp_core::ecdsa;
use std::error::Error;
use std::fmt::{Debug, Display};

pub trait EventMetadata<Env: GadgetEnvironment> {
    fn number(&self) -> <Env as GadgetEnvironment>::Clock;
}

pub trait GadgetEnvironment: Sized + 'static
where
    Self::WorkManager: WorkManagerInterface<
        Clock = Self::Clock,
        RetryID = Self::RetryID,
        TaskID = Self::TaskID,
        SessionID = Self::SessionID,
        Error = Self::Error,
        ProtocolMessage = Self::ProtocolMessage,
    >,
{
    type Event: EventMetadata<Self> + Send + Sync + 'static;
    type ProtocolMessage: Send + Sync + 'static + ProtocolMessageMetadata<Self::WorkManager>;
    type Client: ClientWithApi<Self> + Send + Sync + 'static;
    type WorkManager: WorkManagerInterface;
    type Error: Error + Send + Sync + From<String> + Into<crate::Error> + 'static;
    type Clock: Display + Copy + Send + Sync + 'static;
    type RetryID: Display + Copy + Send + Sync + 'static;
    type TaskID: Debug + Copy + Send + Sync + 'static;
    type SessionID: Display + Copy + Send + Sync + 'static;
    type TransactionManager: TransactionManager;

    #[allow(clippy::too_many_arguments)]
    fn build_protocol_message<Payload: Serialize>(
        associated_block_id: Self::Clock,
        associated_session_id: Self::SessionID,
        associated_retry_id: Self::RetryID,
        associated_task_id: Self::TaskID,
        from: u16,
        to: Option<u16>,
        payload: &Payload,
        from_account_id: Option<ecdsa::Public>,
        to_network_id: Option<ecdsa::Public>,
    ) -> Self::ProtocolMessage;

    fn set_payload(&mut self, input: Vec<u8>, output: &mut Vec<u8>) {
        *output = input;
    }
}

#[derive(Default)]
pub struct TangleEnvironment;

impl GadgetEnvironment for TangleEnvironment {
    type Event = TangleEvent;
    type ProtocolMessage = TangleProtocolMessage;
    type Client = TangleRuntime;
    type WorkManager = TangleWorkManager;
    type Error = crate::Error;
    type Clock = <Self::WorkManager as WorkManagerInterface>::Clock;
    type RetryID = <Self::WorkManager as WorkManagerInterface>::RetryID;
    type TaskID = <Self::WorkManager as WorkManagerInterface>::TaskID;
    type SessionID = <Self::WorkManager as WorkManagerInterface>::SessionID;
    type TransactionManager = TangleTransactionManager;

    fn build_protocol_message<Payload: Serialize>(
        associated_block_id: Self::Clock,
        associated_session_id: Self::SessionID,
        associated_retry_id: Self::RetryID,
        associated_task_id: Self::TaskID,
        from: UserID,
        to: Option<UserID>,
        payload: &Payload,
        from_account_id: Option<ecdsa::Public>,
        to_network_id: Option<ecdsa::Public>,
    ) -> Self::ProtocolMessage {
        TangleProtocolMessage {
            associated_block_id,
            associated_session_id,
            associated_retry_id,
            task_hash: associated_task_id,
            from,
            to,
            payload: serialize(payload).expect("Failed to serialize message"),
            from_network_id: from_account_id,
            to_network_id,
        }
    }
}

impl EventMetadata<TangleEnvironment> for TangleEvent {
    fn number(&self) -> <TangleEnvironment as GadgetEnvironment>::Clock {
        self.number
    }
}
