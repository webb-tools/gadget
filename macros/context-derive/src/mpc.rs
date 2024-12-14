use quote::quote;
use syn::DeriveInput;

use crate::cfg::FieldInfo;

/// Generate the `MPCContext` implementation for the given struct.
#[allow(clippy::too_many_lines)]
pub fn generate_context_impl(
    DeriveInput {
        ident: name,
        generics,
        ..
    }: DeriveInput,
    config_field: FieldInfo,
) -> proc_macro2::TokenStream {
    let _field_access = match config_field {
        FieldInfo::Named(ident) => quote! { self.#ident },
        FieldInfo::Unnamed(index) => quote! { self.#index },
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        #[gadget_sdk::async_trait::async_trait]
        impl #impl_generics gadget_sdk::contexts::MPCContext for #name #ty_generics #where_clause {
            /// Returns a reference to the configuration
            #[inline]
            fn config(&self) -> &gadget_sdk::config::StdGadgetConfiguration {
                &self.config
            }

            /// Returns the network protocol identifier for this context
            #[inline]
            fn network_protocol(&self) -> String {
                let name = stringify!(#name).to_string();
                format!("/{}/1.0.0", name.to_lowercase())
            }

            fn create_network_delivery_wrapper<M>(
                &self,
                mux: std::sync::Arc<gadget_sdk::network::NetworkMultiplexer>,
                party_index: gadget_sdk::round_based::PartyIndex,
                task_hash: [u8; 32],
                parties: std::collections::BTreeMap<gadget_sdk::round_based::PartyIndex, gadget_sdk::subxt_core::ext::sp_core::ecdsa::Public>,
            ) -> Result<gadget_sdk::network::round_based_compat::NetworkDeliveryWrapper<M>, gadget_sdk::Error>
            where
                M: Clone + Send + Unpin + 'static + gadget_sdk::serde::Serialize + gadget_sdk::serde::de::DeserializeOwned + gadget_sdk::round_based::ProtocolMessage,
            {
                Ok(gadget_sdk::network::round_based_compat::NetworkDeliveryWrapper::new(mux, party_index, task_hash, parties))
            }

            async fn get_party_index(
                &self,
            ) -> Result<gadget_sdk::round_based::PartyIndex, gadget_sdk::Error> {
                Ok(self.get_party_index_and_operators().await?.0 as _)
            }

            async fn get_participants(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<gadget_sdk::clients::tangle::runtime::TangleConfig>,
            ) -> Result<
                    std::collections::BTreeMap<gadget_sdk::round_based::PartyIndex, gadget_sdk::subxt::utils::AccountId32>,
                    gadget_sdk::Error,
                > {
                Ok(self.get_party_index_and_operators().await?.1.into_iter().enumerate().map(|(i, (id, _))| (i as _, id)).collect())
            }

            /// Retrieves the current blueprint ID from the configuration
            ///
            /// # Errors
            /// Returns an error if the blueprint ID is not found in the configuration
            fn blueprint_id(&self) -> gadget_sdk::color_eyre::Result<u64> {
                self.config()
                    .protocol_specific
                    .tangle()
                    .map(|c| c.blueprint_id)
                    .map_err(|err| gadget_sdk::color_eyre::Report::msg("Blueprint ID not found in configuration: {err}"))
            }

            /// Retrieves the current party index and operator mapping
            ///
            /// # Errors
            /// Returns an error if:
            /// - Failed to retrieve operator keys
            /// - Current party is not found in the operator list
            async fn get_party_index_and_operators(
                &self,
            ) -> gadget_sdk::color_eyre::Result<(usize, std::collections::BTreeMap<gadget_sdk::subxt::utils::AccountId32, gadget_sdk::subxt_core::ext::sp_core::ecdsa::Public>)> {
                let parties = self.current_service_operators_ecdsa_keys().await?;
                let my_id = self.config.first_sr25519_signer()?.account_id();

                gadget_sdk::trace!(
                    "Looking for {my_id:?} in parties: {:?}",
                    parties.keys().collect::<Vec<_>>()
                );

                let index_of_my_id = parties
                    .iter()
                    .position(|(id, _)| id == &my_id)
                    .ok_or_else(|| gadget_sdk::color_eyre::Report::msg("Party not found in operator list"))?;

                Ok((index_of_my_id, parties))
            }

            /// Retrieves the ECDSA keys for all current service operators
            ///
            /// # Errors
            /// Returns an error if:
            /// - Failed to connect to the Tangle client
            /// - Failed to retrieve operator information
            /// - Missing ECDSA key for any operator
            async fn current_service_operators_ecdsa_keys(
                &self,
            ) -> gadget_sdk::color_eyre::Result<std::collections::BTreeMap<gadget_sdk::subxt::utils::AccountId32, gadget_sdk::subxt_core::ext::sp_core::ecdsa::Public>> {
                let client = self.tangle_client().await?;
                let current_blueprint = self.blueprint_id()?;
                let current_service_op = self.current_service_operators(&client).await?;
                let storage = client.storage().at_latest().await?;

                let mut map = std::collections::BTreeMap::new();
                for (operator, _) in current_service_op {
                    let addr = gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::storage()
                        .services()
                        .operators(current_blueprint, &operator);

                    let maybe_pref = storage.fetch(&addr).await.map_err(|err| {
                        gadget_sdk::color_eyre::Report::msg("Failed to fetch operator storage for {operator}: {err}")
                    })?;

                    if let Some(pref) = maybe_pref {
                        let pt = k256::EncodedPoint::from_bytes(&pref.key).unwrap();
                        let compressed_bytes = pt.compress().to_bytes();
                        map.insert(operator, gadget_sdk::subxt_core::ext::sp_core::ecdsa::Public(
                            compressed_bytes.to_vec().try_into().unwrap()
                        ));
                    } else {
                        return Err(gadget_sdk::color_eyre::Report::msg("Missing ECDSA key for operator {operator}"));
                    }
                }

                Ok(map)
            }

            /// Retrieves the current call ID for this job
            ///
            /// # Errors
            /// Returns an error if failed to retrieve the call ID from storage
            async fn current_call_id(&self) -> gadget_sdk::color_eyre::Result<u64> {
                let client = self.tangle_client().await?;
                let addr = gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::storage().services().next_job_call_id();
                let storage = client.storage().at_latest().await?;

                let maybe_call_id = storage
                    .fetch_or_default(&addr)
                    .await
                    .map_err(|err| gadget_sdk::color_eyre::Report::msg("Failed to fetch current call ID: {err}"))?;

                Ok(maybe_call_id.saturating_sub(1))
            }
        }
    }
}
