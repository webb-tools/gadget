use core::fmt::{Debug, Formatter};
use async_trait::async_trait;
use std::collections::BTreeMap;
use subxt_core::utils::AccountId32;
use std::ops::Deref;
use subxt_core::tx::signer::Signer;
use crate::clients::tangle::runtime::TangleConfig;
use crate::contexts::TangleClientContext;

/// `ServicesContext` trait provides access to the current service and current blueprint from the context.
#[allow(clippy::type_complexity)]
#[async_trait]
pub trait ServicesContext {
    type Config: subxt::Config;

    /// Returns a reference to the configuration
    fn config(&self) -> &crate::config::StdGadgetConfiguration;

    async fn current_blueprint(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
    ) -> Result<
        crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::ServiceBlueprint,
        crate::ext::subxt::Error
    > {
        use crate::ext::subxt;
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let blueprint_id = self.blueprint_id()?;
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

    async fn current_blueprint_owner(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
    ) -> Result<crate::ext::subxt::utils::AccountId32, crate::ext::subxt::Error> {
        use crate::ext::subxt;
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;
        let blueprint_id = self.blueprint_id()?;
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

    async fn current_service_operators(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
    ) -> Result<
        Vec<(
            crate::ext::subxt::utils::AccountId32,
            crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_arithmetic::per_things::Percent,
        )>,
        crate::ext::subxt::Error
    > {
        use crate::ext::subxt;
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let service_id = self.service_id()?;
        let service_instance = api::storage().services().instances(service_id);
        let storage = client.storage().at_latest().await?;
        let result = storage.fetch(&service_instance).await?;
        match result {
            Some(instance) => {
                let mut ret = instance.operators.0;
                ret.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(ret)
            },
            None => Err(subxt::Error::Other(format!(
                "Service instance {service_id} is not created, yet"
            ))),
        }
    }

    async fn operators_metadata(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
        operators: Vec<crate::ext::subxt::utils::AccountId32>,
    ) -> Result<
        Vec<(
            AccountId32,
            OperatorMetadata<
                AccountId32,
                Balance,
                AssetId,
                MaxDelegations,
                MaxOperatorBlueprints,
            >
        )>,
        crate::ext::subxt::Error
    > {
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let storage = client.storage().at_latest().await?;
        let mut operator_metadata = Vec::new();

        for operator in operators {
            let metadata_storage_key = api::storage()
                .multi_asset_delegation()
                .operators(operator.clone());
            let operator_metadata_result = storage.fetch(&metadata_storage_key).await?;
            if let Some(metadata) = operator_metadata_result {
                operator_metadata.push((operator, metadata));
            }
        }

        Ok(operator_metadata)
    }

    async fn operator_metadata(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
        operator: crate::ext::subxt::utils::AccountId32,
    ) -> Result<
        Option<
            crate::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_multi_asset_delegation::types::operator::OperatorMetadata<
                crate::ext::subxt::utils::AccountId32,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::burned::Balance,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::accounts_destroyed::AssetId,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxDelegations,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxOperatorBlueprints,
            >
        >,
        crate::ext::subxt::Error,
    > {
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let storage = client.storage().at_latest().await?;
        let metadata_storage_key = api::storage().multi_asset_delegation().operators(operator);
        storage.fetch(&metadata_storage_key).await
    }

    async fn operator_delegations(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
        operators: Vec<crate::ext::subxt::utils::AccountId32>,
    ) -> Result<
        Vec<(
            crate::ext::subxt::utils::AccountId32,
            Option<
                crate::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_multi_asset_delegation::types::delegator::DelegatorMetadata<
                    crate::ext::subxt::utils::AccountId32,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::accounts_destroyed::AssetId,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::burned::Balance,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxWithdrawRequests,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxDelegations,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxUnstakeRequests,
                    crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxDelegatorBlueprints,
                >
            >
        )>,
        crate::ext::subxt::Error,
    > {
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;
        let storage = client.storage().at_latest().await?;
        let mut operator_delegations = Vec::new();

        for operator in operators {
            let delegations_storage_key = api::storage()
                .multi_asset_delegation()
                .delegators(operator.clone());
            let delegations_result = storage.fetch(&delegations_storage_key).await?;

            operator_delegations.push((operator, delegations_result))
        }

        Ok(operator_delegations)
    }

    async fn operator_delegation(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
        operator: crate::ext::subxt::utils::AccountId32,
    ) -> Result<
        Option<
            crate::tangle_subxt::tangle_testnet_runtime::api::runtime_types::pallet_multi_asset_delegation::types::delegator::DelegatorMetadata<
                crate::ext::subxt::utils::AccountId32,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::accounts_destroyed::AssetId,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::burned::Balance,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxWithdrawRequests,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxDelegations,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxUnstakeRequests,
                crate::ext::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_testnet_runtime::MaxDelegatorBlueprints,
            >
        >,
        crate::ext::subxt::Error,
    > {
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let storage = client.storage().at_latest().await?;
        let delegations_storage_key = api::storage().multi_asset_delegation().delegators(operator);
        let delegations_result = storage.fetch(&delegations_storage_key).await?;

        Ok(delegations_result)
    }

    async fn service_instance(
        &self,
        client: &crate::ext::subxt::OnlineClient<Self::Config>,
    ) -> Result<
        crate::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::Service<
            crate::ext::subxt::utils::AccountId32,
            crate::tangle_subxt::tangle_testnet_runtime::api::system::storage::types::number::Number,
            crate::ext::tangle_subxt::tangle_testnet_runtime::api::assets::events::accounts_destroyed::AssetId,
        >,
        crate::ext::subxt::Error,
    >{
        use crate::ext::subxt;
        use crate::ext::tangle_subxt::tangle_testnet_runtime::api;

        let service_id = self.service_id()?;
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

    /// Retrieves the current blueprint ID from the configuration
    ///
    /// # Errors
    /// Returns an error if the blueprint ID is not found in the configuration
    fn blueprint_id(&self) -> Result<u64, crate::subxt::Error> {
        self.config()
            .protocol_specific
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| crate::subxt::Error::from(format!("Blueprint ID not found in configuration: {err}")))
    }

    fn service_id(&self) -> Result<u64, crate::subxt::Error> {
        let service_instance_id = match &self.config().protocol_specific {
            crate::config::ProtocolSpecificSettings::Tangle(settings) => {
                settings.service_id
            }
            _ => {
                return Err(subxt::Error::Other(
                    "Service instance id is only available for Tangle protocol".to_string(),
                ))
            }
        };

        match service_instance_id {
            Some(service_instance_id) => Ok(service_instance_id),
            None => {
                Err(subxt::Error::Other(
                    "Service instance id is not set. Running in Registration mode?".to_string(),
                ))
            }
        }
    }
}

#[derive(Copy, Clone)]
/// A client that contains functionality useful protocols that require party information. Separated from the ServicesContext to organize and have a struct.
///
/// ```ignore, no_run
/// #[derive(ServicesContext, TangleClientContext)]
/// struct MyContext {
///    ...
/// }
///
/// let ctx = MyContext { ... };
/// let my_party_index = ctx.participants().get_party_index().await?;
/// ```
pub struct ParticipantsClient<'a, ClientConfig: subxt::Config = TangleConfig> {
    client: &'a dyn ServicesWithClientExt<ClientConfig>
}

impl<ClientConfig: subxt::Config> Debug for ParticipantsClient<'_, ClientConfig> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let blueprint_id = self.blueprint_id().unwrap_or_default();
        let service_id = self.service_id().unwrap_or_default();
        f.debug_struct("ParticipantsClient")
            .field("blueprint_id", &blueprint_id)
            .field("service_id", &service_id)
            .finish()
    }
}

impl<ClientConfig: subxt::Config> Deref for ParticipantsClient<'_, ClientConfig> {
    type Target = dyn ServicesWithClientExt<ClientConfig>;

    fn deref(&self) -> &Self::Target {
        self.client
    }
}

/// Extension trait for any context that implements both ServicesContext and TangleClientContext
pub trait ServicesWithClientExt<ClientConfig: subxt::Config>: Send + Sync + 'static + ServicesContext<Config = ClientConfig> + TangleClientContext<Config=ClientConfig> {
    fn participants(&self) -> ParticipantsClient<ClientConfig> where Self: Sized {
        ParticipantsClient { client: self }
    }
}

// Automatically implement the extension trait for any context that implements both ServicesContext and TangleClientContext
impl<ClientConfig: subxt::Config, T: Send + Sync + 'static + ServicesContext<Config = ClientConfig> + TangleClientContext<Config=ClientConfig>> ServicesWithClientExt<ClientConfig> for T {}

impl<ClientConfig: subxt::Config> ParticipantsClient<'_, ClientConfig> {
    /// Retrieves the current party index
    pub async fn my_index(
        &self,
    ) -> Result<crate::round_based::PartyIndex, crate::Error> {
        Ok(self.get_party_index_and_operators().await?.0 as _)
    }

    /// Retrieves the current participants in the MPC protocol
    pub async fn get_participants(
        &self,
    ) -> Result<
        std::collections::BTreeMap<crate::round_based::PartyIndex, crate::subxt::utils::AccountId32>,
        crate::Error,
    > {
        Ok(self.get_party_index_and_operators().await?.1.into_iter().enumerate().map(|(i, (id, _))| (i as _, id)).collect())
    }

    /// Retrieves the ECDSA keys for all current service operators
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the Tangle client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn current_service_operators_ecdsa_keys(
        &self,
    ) -> color_eyre::Result<BTreeMap<AccountId32, crate::subxt_core::ext::sp_core::ecdsa::Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let current_service_op = self.current_service_operators(&client).await?;
        let storage = client.storage().at_latest().await?;

        let mut map = std::collections::BTreeMap::new();
        for (operator, _) in current_service_op {
            let addr = crate::ext::tangle_subxt::tangle_testnet_runtime::api::storage()
                .services()
                .operators(current_blueprint, &operator);

            let maybe_pref = storage.fetch(&addr).await.map_err(|err| {
                crate::color_eyre::Report::msg(format!("Failed to fetch operator storage for {operator}: {err}"))
            })?;

            if let Some(pref) = maybe_pref {
                let _ = map.insert(operator, crate::subxt_core::ext::sp_core::ecdsa::Public(pref.key));
            } else {
                return Err(crate::color_eyre::Report::msg(format!("Missing ECDSA key for operator {operator}")));
            }
        }

        Ok(map)
    }

    /// Retrieves the current party index and operator mapping (ECDSA)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators(
        &self,
    ) -> crate::color_eyre::Result<(usize, std::collections::BTreeMap<crate::subxt::utils::AccountId32, crate::subxt_core::ext::sp_core::ecdsa::Public>)> {
        let parties = self.current_service_operators_ecdsa_keys().await?;
        let my_id = self.config().first_sr25519_signer()?.account_id();

        crate::trace!(
                    "Looking for {my_id:?} in parties: {:?}",
                    parties.keys().collect::<Vec<_>>()
                );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id == &my_id)
            .ok_or_else(|| crate::color_eyre::Report::msg("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }

    /// Retrieves the ECDSA keys for all current service operators (SR25519)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to connect to the Tangle client
    /// - Failed to retrieve operator information
    /// - Missing ECDSA key for any operator
    pub async fn current_service_operators_sr25519(
        &self,
    ) -> color_eyre::Result<BTreeMap<AccountId32, crate::subxt_core::ext::sp_core::sr25519::Public>> {
        let client = self.tangle_client().await?;
        let current_service_op = self.current_service_operators(&client).await?;

        let mut map = std::collections::BTreeMap::new();
        for (operator, _) in current_service_op {
            let _ = map.insert(operator.clone(), crate::subxt_core::ext::sp_core::sr25519::Public(operator.0));
        }

        Ok(map)
    }

    ///
    /// # Errors
    /// Returns an error if:
    /// - Failed to retrieve operator keys
    /// - Current party is not found in the operator list
    pub async fn get_party_index_and_operators_sr25519(
        &self,
    ) -> crate::color_eyre::Result<(usize, std::collections::BTreeMap<crate::subxt::utils::AccountId32, crate::subxt_core::ext::sp_core::sr25519::Public>)> {
        let parties = self.current_service_operators_sr25519().await?;
        let my_id = self.config().first_sr25519_signer()?.account_id();

        crate::trace!(
                    "Looking for {my_id:?} in parties: {:?}",
                    parties.keys().collect::<Vec<_>>()
                );

        let index_of_my_id = parties
            .iter()
            .position(|(id, _)| id == &my_id)
            .ok_or_else(|| crate::color_eyre::Report::msg("Party not found in operator list"))?;

        Ok((index_of_my_id, parties))
    }
}