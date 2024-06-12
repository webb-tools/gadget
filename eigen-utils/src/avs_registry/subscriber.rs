use alloy_provider::Provider;
use alloy_pubsub::Subscription;
use alloy_rpc_types::Filter;
use alloy_rpc_types::Log;

use crate::Config;

use super::AvsRegistryContractManager;
use super::AvsRegistryContractResult;

pub trait AvsRegistryChainSubscriberTrait {
    async fn subscribe_to_new_pubkey_registrations(
        &self,
    ) -> AvsRegistryContractResult<Subscription<Log>>;

    async fn subscribe_to_operator_socket_updates(
        &self,
    ) -> AvsRegistryContractResult<Subscription<Log>>;
}

impl<T: Config> AvsRegistryChainSubscriberTrait for AvsRegistryContractManager<T> {
    async fn subscribe_to_new_pubkey_registrations(
        &self,
    ) -> AvsRegistryContractResult<Subscription<Log>> {
        let filter = Filter::new()
            .address(self.bls_apk_registry_addr)
            .event("NewPubkeyRegistration");
        let subscription = self.eth_client_ws.subscribe_logs(&filter).await?;
        Ok(subscription)
    }

    async fn subscribe_to_operator_socket_updates(
        &self,
    ) -> AvsRegistryContractResult<Subscription<Log>> {
        let filter = Filter::new()
            .address(self.registry_coordinator_addr)
            .event("OperatorSocketUpdate");
        let subscription = self.eth_client_ws.subscribe_logs(&filter).await?;
        Ok(subscription)
    }
}
