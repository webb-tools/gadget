use std::sync::Arc;
use std::time::Duration;

use color_eyre::Result;
use gadget_common::config::ClientWithApi;
use gadget_common::locks::TokioMutexExt;
use gadget_core::gadget::substrate::{Client, FinalityNotification};
use tangle_subxt::subxt::blocks::{Block, BlockRef};
use tangle_subxt::subxt::ext::futures::TryFutureExt;
use tangle_subxt::subxt::utils::AccountId32;
use tangle_subxt::subxt::{self, PolkadotConfig};
use tangle_subxt::tangle_testnet_runtime::api;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxAdditionalParamsLen;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::{
    tangle_primitives::jobs::{PhaseResult, RpcResponseJobsData},
    tangle_primitives::roles::RoleType,
    tangle_testnet_runtime::{
        MaxDataLen, MaxKeyLen, MaxParticipants, MaxProofLen, MaxSignatureLen, MaxSubmissionLen,
    },
};

pub type TangleConfig = subxt::PolkadotConfig;
type TangleClient = subxt::OnlineClient<TangleConfig>;
type TangleBlock = Block<TangleConfig, TangleClient>;
type TangleBlockStream = subxt::backend::StreamOfResults<TangleBlock>;

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

#[derive(Debug, Clone)]
pub struct TangleRuntime {
    client: subxt::OnlineClient<PolkadotConfig>,
    finality_notification_stream: Arc<tokio::sync::Mutex<Option<TangleBlockStream>>>,
    latest_finality_notification: Arc<tokio::sync::Mutex<Option<FinalityNotification>>>,
}

impl TangleRuntime {
    /// Create a new TangleRuntime instance.
    pub fn new(client: subxt::OnlineClient<PolkadotConfig>) -> Self {
        Self {
            client,
            finality_notification_stream: Arc::new(tokio::sync::Mutex::new(None)),
            latest_finality_notification: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn client(&self) -> subxt::OnlineClient<PolkadotConfig> {
        self.client.clone()
    }

    /// Initialize the TangleRuntime instance by listening for finality notifications.
    /// This method must be called before using the instance.
    async fn initialize(&self) -> Result<()> {
        let finality_notification_stream = self.client.blocks().subscribe_finalized().await?;
        *self.finality_notification_stream.lock().await = Some(finality_notification_stream);
        Ok(())
    }

    fn runtime_api(
        &self,
        at: [u8; 32],
    ) -> subxt::runtime_api::RuntimeApi<TangleConfig, TangleClient> {
        let block_ref = BlockRef::from_hash(sp_core::hash::H256::from_slice(&at));
        self.client.runtime_api().at(block_ref)
    }
}

#[async_trait::async_trait]
impl Client for TangleRuntime {
    async fn get_next_finality_notification(&self) -> Option<FinalityNotification> {
        let mut lock = self
            .finality_notification_stream
            .try_lock_timeout(Duration::from_millis(500))
            .await
            .ok()?;
        match lock.as_mut() {
            Some(stream) => {
                let block = stream.next().await?.ok()?;
                let notification = FinalityNotification {
                    number: block.number().into(),
                    hash: block.hash().into(),
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
                tracing::debug!("Finality notification stream is not initialized. Initializing...");
                self.initialize().await.ok()?;
                // Next time, the stream should be initialized.
                self.get_next_finality_notification().await
            }
        }
    }

    async fn get_latest_finality_notification(&self) -> Option<FinalityNotification> {
        let lock = self
            .latest_finality_notification
            .try_lock_timeout(Duration::from_millis(500))
            .await
            .ok()?;
        match &*lock {
            Some(notification) => Some(notification.clone()),
            None => {
                drop(lock);
                tracing::debug!("Latest finality notification is not available. Fetching...");
                self.get_next_finality_notification().await
            }
        }
    }
}

#[async_trait::async_trait]
impl ClientWithApi for TangleRuntime {
    async fn query_jobs_by_validator(
        &self,
        at: [u8; 32],
        validator: AccountId32,
    ) -> core::result::Result<
        Option<
            Vec<
                RpcResponseJobsData<
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
        let q = api::apis().jobs_api().query_jobs_by_validator(validator);
        self.runtime_api(at)
            .call(q)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }

    async fn query_job_by_id(
        &self,
        at: [u8; 32],
        role_type: RoleType,
        job_id: u64,
    ) -> core::result::Result<
        Option<
            RpcResponseJobsData<
                AccountId32,
                u64,
                MaxParticipants,
                MaxSubmissionLen,
                MaxAdditionalParamsLen,
            >,
        >,
        gadget_common::Error,
    > {
        let q = api::apis().jobs_api().query_job_by_id(role_type, job_id);
        self.runtime_api(at)
            .call(q)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }

    async fn query_job_result(
        &self,
        at: [u8; 32],
        role_type: RoleType,
        job_id: u64,
    ) -> core::result::Result<
        Option<
            PhaseResult<
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
        let q = api::apis().jobs_api().query_job_result(role_type, job_id);
        self.runtime_api(at)
            .call(q)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }

    async fn query_next_job_id(
        &self,
        at: [u8; 32],
    ) -> core::result::Result<u64, gadget_common::Error> {
        let q = api::apis().jobs_api().query_next_job_id();
        self.runtime_api(at)
            .call(q)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }

    async fn query_restaker_role_key(
        &self,
        at: [u8; 32],
        address: AccountId32,
    ) -> core::result::Result<Option<Vec<u8>>, gadget_common::Error> {
        let q = api::apis().jobs_api().query_restaker_role_key(address);
        self.runtime_api(at)
            .call(q)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }

    async fn query_restaker_roles(
        &self,
        at: [u8; 32],
        address: AccountId32,
    ) -> std::result::Result<Vec<RoleType>, gadget_common::Error> {
        let storage_address = api::storage().roles().account_roles_mapping(address);
        let block_ref = BlockRef::from_hash(sp_core::hash::H256::from_slice(&at));
        self.client
            .storage()
            .at(block_ref)
            .fetch_or_default(&storage_address)
            .map_ok(|v| v.0)
            .map_err(|e| gadget_common::Error::ClientError { err: e.to_string() })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use color_eyre::{eyre::OptionExt, Result};

    #[ignore = "requires a running node"]
    #[tokio::test]
    async fn client() -> Result<()> {
        let subxt_client = subxt::OnlineClient::new().await?;
        let runtime = TangleRuntime::new(subxt_client);

        let notification = runtime
            .get_next_finality_notification()
            .await
            .ok_or_eyre("Finality notification not found")?;
        let job_id = runtime.query_next_job_id(notification.hash).await?;
        eprintln!("Next job id: {}", job_id);
        Ok(())
    }
}
