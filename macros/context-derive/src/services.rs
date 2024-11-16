use quote::quote;
use syn::DeriveInput;

use crate::cfg::FieldInfo;

/// Generate the `ServicesContext` implementation for the given struct.
#[allow(clippy::too_many_lines)]
pub fn generate_context_impl(
    DeriveInput {
        ident: name,
        generics,
        ..
    }: DeriveInput,
    config_field: FieldInfo,
) -> proc_macro2::TokenStream {
    let field_access = match config_field {
        FieldInfo::Named(ident) => quote! { self.#ident },
        FieldInfo::Unnamed(index) => quote! { self.#index },
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    quote! {
        impl #impl_generics gadget_sdk::ctx::ServicesContext for #name #ty_generics #where_clause {
            type Config = gadget_sdk::ext::subxt::PolkadotConfig;
            fn current_blueprint(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
            ) -> impl core::future::Future<
                Output = Result<
                    gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::ServiceBlueprint,
                    gadget_sdk::ext::subxt::Error
                >
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                async move {
                    let blueprint_id = match #field_access.protocol_specific {
                        gadget_sdk::config::ProtocolSpecificSettings::Tangle(settings) => settings.blueprint_id,
                        _ => return Err(subxt::Error::Other("Blueprint id is only available for Tangle protocol".to_string())),
                    };
                    let blueprint = api::storage().services().blueprints(blueprint_id);
                    let storage = client.storage().at_latest().await?;
                    let result = storage.fetch(&blueprint).await?;
                    match result {
                        Some((_, blueprint)) => Ok(blueprint),
                        None => Err(subxt::Error::Other(format!(
                            "Blueprint with id {blueprint_id} not found"
                        ))),
                    }
                }
            }

            fn current_blueprint_owner(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
            ) -> impl core::future::Future<Output = Result<gadget_sdk::ext::subxt::utils::AccountId32, gadget_sdk::ext::subxt::Error>> {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;
                async move {
                    let blueprint_id = match #field_access.protocol_specific {
                        gadget_sdk::config::ProtocolSpecificSettings::Tangle(settings) => settings.blueprint_id,
                        _ => return Err(subxt::Error::Other("Blueprint id is only available for Tangle protocol".to_string())),
                    };
                    let blueprint = api::storage().services().blueprints(blueprint_id);
                    let storage = client.storage().at_latest().await?;
                    let result = storage.fetch(&blueprint).await?;
                    match result {
                        Some((account_id, _)) => Ok(account_id),
                        None => Err(subxt::Error::Other(format!(
                            "Blueprint with id {blueprint_id} not found"
                        ))),
                    }
                }
            }

            fn current_service_operators(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
            ) -> impl core::future::Future<
                Output = Result<
                    Vec<(
                        gadget_sdk::ext::subxt::utils::AccountId32,
                        gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_arithmetic::per_things::Percent,
                    )>,
                    gadget_sdk::ext::subxt::Error
                >
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                async move {
                    let service_instance_id = match #field_access.protocol_specific {
                        gadget_sdk::config::ProtocolSpecificSettings::Tangle(settings) => settings.service_id,
                        _ => return Err(subxt::Error::Other("Service instance id is only available for Tangle protocol".to_string())),
                    };
                    let service_id = match service_instance_id {
                      Some(service_instance_id) => service_instance_id,
                      None => return Err(subxt::Error::Other("Service instance id is not set. Running in Registration mode?".to_string())),
                    };
                    let service_instance = api::storage().services().instances(service_id);
                    let storage = client.storage().at_latest().await?;
                    let result = storage.fetch(&service_instance).await?;
                    match result {
                        Some(instance) => Ok(instance.operators.0),
                        None => Err(subxt::Error::Other(format!(
                            "Service instance {service_id} is not created, yet"
                        ))),
                    }
                }
            }

            fn get_operators_metadata(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
                operators: Vec<gadget_sdk::ext::subxt::utils::AccountId32>,
            ) -> impl core::future::Future<
                Output = Result<
                    Vec<(
                        gadget_sdk::ext::subxt::utils::AccountId32,
                        gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_multi_asset_delegations::types::OperatorMetadata,
                    )>,
                    gadget_sdk::ext::subxt::Error
                >
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                async move {
                    let storage = client.storage().at_latest().await?;
                    let mut operator_metadata = Vec::new();

                    for operator in operators {
                        let metadata_storage_key = api::storage().multi_asset_delgations().operators(operator.clone());
                        let operator_metadata_result = storage.fetch(&metadata_storage_key).await?;
                        if let Some(metadata) = operator_metadata_result {
                            operator_metadata.push((operator, metadata));
                        }
                    }

                    Ok(operator_metadata)
                }
            }

            async fn get_operator_metadata(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
                operator: gadget_sdk::ext::subxt::utils::AccountId32,
            ) -> Result<
                Option<gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_multi_asset_delegations::types::OperatorMetadata>,
                gadget_sdk::ext::subxt::Error,
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                let storage = client.storage().at_latest().await?;
                let metadata_storage_key = api::storage().multi_asset_delgations().operators(operator);
                storage.fetch(&metadata_storage_key).await
            }

            async fn get_operator_delegations(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
                operators: Vec<gadget_sdk::ext::subxt::utils::AccountId32>,
            ) -> Result<
                Vec<(
                    gadget_sdk::ext::subxt::utils::AccountId32, // operator
                    gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_std::collections::btree_map::BTreeMap<
                        gadget_sdk::ext::subxt::utils::AccountId32, // delegator
                        gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_std::collections::btree_map::BTreeMap<
                            gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_assets::types::AssetId,
                            gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_balances::types::Balance,
                        >
                    >
                )>,
                gadget_sdk::ext::subxt::Error,
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;
                use gadget_sdk::ext::subxt::utils::AccountId32;
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::{
                    sp_std::collections::btree_map::BTreeMap,
                    pallet_assets::types::AssetId,
                    pallet_balances::types::Balance,
                };

                let storage = client.storage().at_latest().await?;
                let mut operator_delegations: Vec<(AccountId32, BTreeMap<AccountId32, BTreeMap<AssetId, Balance>>)> = Vec::new();

                for operator in operators {
                    let delegations_storage_key = api::storage().multi_asset_delgations().delegations_to(operator.clone());
                    let delegations_result = storage.fetch(&delegations_storage_key).await?;

                    if let Some(delegations) = delegations_result {
                        operator_delegations.push((operator, delegations.0));
                    }
                }

                Ok(operator_delegations)
            }

            async fn get_operator_delegation(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
                operator: gadget_sdk::ext::subxt::utils::AccountId32,
            ) -> Result<
                gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_std::collections::btree_map::BTreeMap<
                    gadget_sdk::ext::subxt::utils::AccountId32, // delegator
                    gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_std::collections::btree_map::BTreeMap<
                        gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_assets::types::AssetId,
                        gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_balances::types::Balance,
                    >
                >,
                gadget_sdk::ext::subxt::Error,
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                let storage = client.storage().at_latest().await?;
                let delegations_storage_key = api::storage().multi_asset_delgations().delegations_to(operator);
                let delegations_result = storage.fetch(&delegations_storage_key).await?;

                match delegations_result {
                    Some(delegations) => Ok(delegations.0),
                    None => Ok(Default::default()),
                }
            }

            async fn get_service_instance(
                &self,
                client: &gadget_sdk::ext::subxt::OnlineClient<Self::Config>,
            ) -> Result<
                gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_services::types::Service,
                gadget_sdk::ext::subxt::Error,
            > {
                use gadget_sdk::ext::tangle_subxt::tangle_testnet_runtime::api;
                use gadget_sdk::ext::subxt;

                let service_instance_id = match &#field_access.protocol_specific {
                    gadget_sdk::config::ProtocolSpecificSettings::Tangle(settings) => settings.service_instance_id,
                    _ => return Err(subxt::Error::Other("Service instance id is only available for Tangle protocol".to_string())),
                };
                let service_id = match service_instance_id {
                    Some(service_instance_id) => service_instance_id,
                    None => return Err(subxt::Error::Other("Service instance id is not set. Running in Registration mode?".to_string())),
                };
                let service_instance = api::storage().services().instances(service_id);
                let storage = client.storage().at_latest().await?;
                let result = storage.fetch(&service_instance).await?;
                match result {
                    Some(instance) => Ok(instance),
                    None => Err(subxt::Error::Other(format!(
                        "Service instance {service_id} is not created, yet"
                    ))),
                }
            }
        }
    }
}
