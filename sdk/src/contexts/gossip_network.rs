use crate::contexts::ServicesContext;

/// `GossipNetworkContext` trait provides access to the network client from the context.
pub trait GossipNetworkContext {
    /// Creates a network delivery wrapper for MPC communication
    fn create_network_delivery_wrapper<M>(
        &self,
        mux: std::sync::Arc<crate::network::NetworkMultiplexer>,
        party_index: crate::round_based::PartyIndex,
        task_hash: [u8; 32],
        parties: std::collections::BTreeMap<crate::round_based::PartyIndex, crate::subxt_core::ext::sp_core::ecdsa::Public>,
    ) -> Result<crate::network::round_based_compat::NetworkDeliveryWrapper<M>, crate::Error>
    where
        M: Clone + Send + Unpin + 'static + crate::serde::Serialize + crate::serde::de::DeserializeOwned + crate::round_based::ProtocolMessage,
    {
        Ok(crate::network::round_based_compat::NetworkDeliveryWrapper::new(mux, party_index, task_hash, parties))
    }
}

impl<T: ServicesContext> GossipNetworkContext for T {}