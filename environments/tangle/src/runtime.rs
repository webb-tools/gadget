use std::sync::Arc;
use std::time::Duration;

use crate::gadget::TangleEvent;
use gadget_common::locks::TokioMutexExt;
use gadget_common::tangle_subxt::subxt::blocks::{Block, BlockRef};
use gadget_common::tangle_subxt::subxt::{self, SubstrateConfig};
use gadget_common::{async_trait, tangle_runtime::*};
use gadget_core::gadget::general::Client;

pub type TangleConfig = SubstrateConfig;
pub type TangleClient = subxt::OnlineClient<TangleConfig>;
pub type TangleBlock = Block<TangleConfig, TangleClient>;
pub type TangleBlockStream = subxt::backend::StreamOfResults<TangleBlock>;

pub mod crypto {
    use sp_application_crypto::{app_crypto, ecdsa, sr25519};
    pub mod acco {
        use super::*;
        pub use sp_core::crypto::key_types::ACCOUNT as KEY_TYPE;
        app_crypto!(sr25519, KEY_TYPE);
    }

    pub mod role {
        use super::*;
        /// Key type for ROLE keys
        pub const KEY_TYPE: sp_application_crypto::KeyTypeId =
            sp_application_crypto::KeyTypeId(*b"role");

        app_crypto!(ecdsa, KEY_TYPE);
    }
}

#[derive(Clone)]
pub struct TangleRuntime {
    client: subxt::OnlineClient<SubstrateConfig>,
    finality_notification_stream:
        Arc<gadget_common::gadget_io::tokio::sync::Mutex<Option<TangleBlockStream>>>,
    latest_finality_notification:
        Arc<gadget_common::gadget_io::tokio::sync::Mutex<Option<TangleEvent>>>,
    account_id: AccountId32,
}

impl TangleRuntime {
    /// Create a new TangleRuntime instance.
    pub fn new(client: subxt::OnlineClient<SubstrateConfig>, account_id: AccountId32) -> Self {
        Self {
            client,
            finality_notification_stream: Arc::new(
                gadget_common::gadget_io::tokio::sync::Mutex::new(None),
            ),
            latest_finality_notification: Arc::new(
                gadget_common::gadget_io::tokio::sync::Mutex::new(None),
            ),
            account_id,
        }
    }

    pub fn client(&self) -> subxt::OnlineClient<SubstrateConfig> {
        self.client.clone()
    }

    /// Initialize the TangleRuntime instance by listening for finality notifications.
    /// This method must be called before using the instance.
    async fn initialize(&self) -> gadget_common::color_eyre::Result<()> {
        let finality_notification_stream = self.client.blocks().subscribe_finalized().await?;
        *self.finality_notification_stream.lock().await = Some(finality_notification_stream);
        Ok(())
    }

    pub fn runtime_api(
        &self,
        at: [u8; 32],
    ) -> subxt::runtime_api::RuntimeApi<TangleConfig, TangleClient> {
        let block_ref = BlockRef::from_hash(sp_core::hash::H256::from_slice(&at));
        self.client.runtime_api().at(block_ref)
    }

    pub fn account_id(&self) -> &AccountId32 {
        &self.account_id
    }
}

#[async_trait::async_trait]
impl Client<TangleEvent> for TangleRuntime {
    async fn next_event(&self) -> Option<TangleEvent> {
        let mut lock = self
            .finality_notification_stream
            .try_lock_timeout(Duration::from_millis(500))
            .await
            .ok()?;
        match lock.as_mut() {
            Some(stream) => {
                let block = stream.next().await?.ok()?;
                let events = block.events().await.ok()?;
                let notification = TangleEvent {
                    number: block.number().into(),
                    hash: block.hash().into(),
                    events,
                };
                let mut lock2 = self
                    .latest_finality_notification
                    .lock_timeout(Duration::from_millis(500))
                    .await;
                *lock2 = Some(notification.clone());
                Some(notification)
            }
            None => {
                drop(lock);
                self.initialize().await.ok()?;
                // Next time, the stream should be initialized.
                self.next_event().await
            }
        }
    }

    async fn latest_event(&self) -> Option<TangleEvent> {
        let lock = self
            .latest_finality_notification
            .try_lock_timeout(Duration::from_millis(500))
            .await
            .ok()?;
        match &*lock {
            Some(notification) => Some(notification.clone()),
            None => {
                drop(lock);
                self.next_event().await
            }
        }
    }
}
