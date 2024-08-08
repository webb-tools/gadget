use crate::gadget::TangleEvent;
use crate::runtime::TangleConfig;
use crate::work_manager::TangleWorkManager;
use environment_utils::transaction_manager::tangle::{SubxtPalletSubmitter, TanglePalletSubmitter};
use gadget::{SubxtConfig, TangleJobMetadata};
use gadget_common::async_trait::async_trait;
use gadget_common::channels::UserID;
use gadget_common::client::PairSigner;
use gadget_common::config::DebugLogger;
use gadget_common::environments::{EventMetadata, GadgetEnvironment};
use gadget_common::tangle_subxt::subxt::tx::Signer;
use gadget_common::utils::serialize;
use gadget_common::WorkManagerInterface;
use message::TangleProtocolMessage;
use runtime::TangleRuntime;
use sp_core::serde::Serialize;
use sp_core::{ecdsa, sr25519};
use std::sync::Arc;

pub mod api;
pub mod gadget;
pub mod message;
pub mod runtime;
pub mod work_manager;

pub type TangleTransactionManager = Arc<dyn TanglePalletSubmitter>;

#[derive(Clone)]
pub struct TangleEnvironment {
    pub subxt_config: SubxtConfig,
    pub account_key: sr25519::Pair,
    pub logger: DebugLogger,
    pub tx_manager: Arc<parking_lot::Mutex<Option<TangleTransactionManager>>>,
}

impl TangleEnvironment {
    pub fn new(subxt_config: SubxtConfig, account_key: sr25519::Pair, logger: DebugLogger) -> Self {
        Self {
            subxt_config,
            account_key,
            logger,
            tx_manager: Arc::new(parking_lot::Mutex::new(None)),
        }
    }
}

impl std::fmt::Debug for TangleEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TangleEnvironment")
            .field("subxt_config", &self.subxt_config)
            .finish()
    }
}

#[async_trait]
impl GadgetEnvironment for TangleEnvironment {
    type Event = TangleEvent;
    type ProtocolMessage = TangleProtocolMessage;
    type Client = TangleRuntime;
    type WorkManager = TangleWorkManager;
    type Error = gadget_common::Error;
    type Clock = <Self::WorkManager as WorkManagerInterface>::Clock;
    type RetryID = <Self::WorkManager as WorkManagerInterface>::RetryID;
    type TaskID = <Self::WorkManager as WorkManagerInterface>::TaskID;
    type SessionID = <Self::WorkManager as WorkManagerInterface>::SessionID;
    type TransactionManager = TangleTransactionManager;
    type JobInitMetadata = TangleJobMetadata;

    fn build_protocol_message<Payload: Serialize>(
        associated_block_id: <Self::WorkManager as WorkManagerInterface>::Clock,
        associated_session_id: <Self::WorkManager as WorkManagerInterface>::SessionID,
        associated_retry_id: <Self::WorkManager as WorkManagerInterface>::RetryID,
        associated_task_id: <Self::WorkManager as WorkManagerInterface>::TaskID,
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

    async fn setup_runtime(&self) -> Result<Self::Client, Self::Error> {
        let subxt_client =
            gadget_common::tangle_subxt::subxt::OnlineClient::<TangleConfig>::from_url(
                &self.subxt_config.endpoint,
            )
            .await
            .map_err(|err| gadget_common::Error::ClientError {
                err: err.to_string(),
            })?;

        let pair_signer = PairSigner::new(self.account_key.clone());
        let account_id = pair_signer.account_id();
        let mut lock = self.tx_manager.lock();

        if lock.is_none() {
            let tx_manager_submitter = SubxtPalletSubmitter::with_client(
                subxt_client.clone(),
                pair_signer,
                self.logger.clone(),
            );
            *lock = Some(Arc::new(tx_manager_submitter));
        }

        Ok(TangleRuntime::new(subxt_client, account_id))
    }

    fn transaction_manager(&self) -> Self::TransactionManager {
        let lock = self.tx_manager.lock();
        if let Some(tx_manager) = &*lock {
            tx_manager.clone()
        } else {
            panic!("Transaction manager not initialized")
        }
    }
}

impl EventMetadata<TangleEnvironment> for TangleEvent {
    fn number(&self) -> <TangleEnvironment as GadgetEnvironment>::Clock {
        self.number
    }
}
