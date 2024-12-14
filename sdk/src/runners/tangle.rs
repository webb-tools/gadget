use crate::config::ProtocolSpecificSettings;
use crate::{config::GadgetConfiguration, runners::RunnerError};
use crate::{info, tx};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::EncodedPoint;
use sp_core::Pair;
use subxt::tx::Signer;
use tangle_subxt::tangle_testnet_runtime::api;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::PriceTargets as TanglePriceTargets;
use tangle_subxt::tangle_testnet_runtime::api::services::calls::types::register::RegistrationArgs;

use super::BlueprintConfig;

/// Wrapper for `tangle_subxt`'s [`PriceTargets`]
///
/// This provides a [`Default`] impl for a zeroed-out [`PriceTargets`].
///
/// [`PriceTargets`]: tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::PriceTargets
#[derive(Clone)]
pub struct PriceTargets(TanglePriceTargets);

impl From<TanglePriceTargets> for PriceTargets {
    fn from(t: TanglePriceTargets) -> Self {
        PriceTargets(t)
    }
}

impl Default for PriceTargets {
    fn default() -> Self {
        Self(TanglePriceTargets {
            cpu: 0,
            mem: 0,
            storage_hdd: 0,
            storage_ssd: 0,
            storage_nvme: 0,
        })
    }
}

#[derive(Clone, Default)]
pub struct TangleConfig {
    pub price_targets: PriceTargets,
}

#[async_trait::async_trait]
impl BlueprintConfig for TangleConfig {
    async fn requires_registration(
        &self,
        env: &GadgetConfiguration<parking_lot::RawRwLock>,
    ) -> Result<bool, RunnerError> {
        requires_registration_impl(env).await
    }

    async fn register(
        &self,
        env: &GadgetConfiguration<parking_lot::RawRwLock>,
    ) -> Result<(), RunnerError> {
        register_impl(self.clone().price_targets, vec![], env).await
    }
}

pub async fn requires_registration_impl(
    env: &GadgetConfiguration<parking_lot::RawRwLock>,
) -> Result<bool, RunnerError> {
    if env.skip_registration {
        return Ok(false);
    }

    // Get the blueprint_id from the Tangle protocol specific settings
    let blueprint_id = match &env.protocol_specific {
        ProtocolSpecificSettings::Tangle(settings) => settings.blueprint_id,
        _ => {
            return Err(RunnerError::InvalidProtocol(
                "Expected Tangle protocol".into(),
            ))
        }
    };

    // Check if the operator is already registered
    let client = env.client().await?;
    let signer = env.first_sr25519_signer()?;
    let account_id = signer.account_id();

    let operator_profile_query = api::storage().services().operators_profile(account_id);
    let operator_profile = client
        .storage()
        .at_latest()
        .await?
        .fetch(&operator_profile_query)
        .await?;
    let is_registered = operator_profile
        .map(|p| p.blueprints.0.iter().any(|&id| id == blueprint_id))
        .unwrap_or(false);

    Ok(!is_registered)
}

pub async fn register_impl(
    price_targets: PriceTargets,
    registration_args: RegistrationArgs,
    env: &GadgetConfiguration<parking_lot::RawRwLock>,
) -> Result<(), RunnerError> {
    let client = env.client().await?;
    let signer = env.first_sr25519_signer()?;
    let ecdsa_pair = env.first_ecdsa_signer()?;

    // Parse Tangle protocol specific settings
    let ProtocolSpecificSettings::Tangle(blueprint_settings) = &env.protocol_specific else {
        return Err(RunnerError::InvalidProtocol(
            "Expected Tangle protocol".into(),
        ));
    };

    let account_id = signer.account_id();
    // Check if the operator is active operator.
    let operator_active_query = api::storage()
        .multi_asset_delegation()
        .operators(account_id);
    let operator_active = client
        .storage()
        .at_latest()
        .await?
        .fetch(&operator_active_query)
        .await?;
    if operator_active.is_none() {
        return Err(RunnerError::NotActiveOperator);
    }

    let blueprint_id = blueprint_settings.blueprint_id;
    let secret = SigningKey::from_slice(&ecdsa_pair.signer().seed())
        .expect("Should be able to create a secret key from a seed");
    let verifying_key = VerifyingKey::from(secret);
    let public_key = verifying_key.to_encoded_point(false);
    let key = public_key.to_bytes().to_vec().try_into().unwrap();

    let xt = api::tx().services().register(
        blueprint_id,
        services::OperatorPreferences {
            key,
            price_targets: price_targets.clone().0,
        },
        registration_args,
        0,
    );

    // send the tx to the tangle and exit.
    let result = tx::tangle::send(&client, &signer, &xt).await?;
    info!("Registered operator with hash: {:?}", result);
    Ok(())
}
