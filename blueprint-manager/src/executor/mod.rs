use crate::config::BlueprintManagerConfig;
use crate::utils;
use color_eyre::eyre::OptionExt;
use color_eyre::Report;
use gadget_common::config::DebugLogger;
use gadget_common::environments::GadgetEnvironment;
use gadget_common::subxt_signer::sr25519;
use gadget_common::tangle_runtime::AccountId32;
use gadget_io::{defaults, GadgetConfig};
use shell_sdk::entry::{keystore_from_base_path, node_key_to_bytes};
use shell_sdk::keystore::load_keys_from_keystore;
use shell_sdk::{Client, SendFuture};
use sp_core::{ecdsa, Pair};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tangle_environment::api::ServicesClient;
use tangle_environment::gadget::SubxtConfig;
use tangle_environment::TangleEnvironment;
use tokio::task::JoinHandle;

pub(crate) mod event_handler;

pub struct BlueprintManagerHandle {
    shutdown_call: Option<tokio::sync::oneshot::Sender<()>>,
    start_tx: Option<tokio::sync::oneshot::Sender<()>>,
    process: JoinHandle<color_eyre::Result<()>>,
    logger: DebugLogger,
    sr25519_id: sr25519::Keypair,
    ecdsa_id: ecdsa::Pair,
}

impl BlueprintManagerHandle {
    /// Send a start signal to the blueprint manager
    pub fn start(&mut self) -> color_eyre::Result<()> {
        match self.start_tx.take() {
            Some(tx) => match tx.send(()) {
                Ok(_) => {
                    self.logger.info("Start signal sent to Blueprint Manager");
                    Ok(())
                }
                Err(_) => Err(Report::msg(
                    "Failed to send start signal to Blueprint Manager",
                )),
            },
            None => Err(Report::msg("Blueprint Manager Already Started")),
        }
    }

    /// Returns the SR25519 keypair for this blueprint manager
    pub fn sr25519_id(&self) -> &sr25519::Keypair {
        &self.sr25519_id
    }

    /// Returns the ECDSA keypair for this blueprint manager
    pub fn ecdsa_id(&self) -> &ecdsa::Pair {
        &self.ecdsa_id
    }

    /// Shutdown the blueprint manager
    pub async fn shutdown(&mut self) -> color_eyre::Result<()> {
        self.shutdown_call
            .take()
            .map(|tx| tx.send(()))
            .ok_or_eyre("Shutdown already called")?
            .map_err(|_| Report::msg("Failed to send shutdown signal to Blueprint Manager"))
    }
}

/// Add default behavior for unintentional dropping of the BlueprintManagerHandle
/// This will ensure that the BlueprintManagerHandle is executed even if the handle
/// is dropped, which is similar behavior to the tokio SpawnHandle
impl Drop for BlueprintManagerHandle {
    fn drop(&mut self) {
        let _ = self.start();
    }
}

/// Implement the Future trait for the BlueprintManagerHandle to allow
/// for the handle to be awaited on
impl Future for BlueprintManagerHandle {
    type Output = color_eyre::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Start the blueprint manager if it has not been started
        let this = self.get_mut();
        if this.start_tx.is_some() {
            if let Err(err) = this.start() {
                return Poll::Ready(Err(err));
            }
        }

        let result = futures::ready!(Pin::new(&mut this.process).poll(cx));

        match result {
            Ok(res) => Poll::Ready(res),
            Err(err) => Poll::Ready(Err(Report::msg(format!(
                "Blueprint Manager Closed Unexpectedly (JoinError): {err:?}"
            )))),
        }
    }
}

pub async fn run_blueprint_manager<F: SendFuture<'static, ()>>(
    blueprint_manager_config: BlueprintManagerConfig,
    gadget_config: GadgetConfig,
    shutdown_cmd: F,
) -> color_eyre::Result<BlueprintManagerHandle> {
    let logger_id = if let Some(custom_id) = &blueprint_manager_config.instance_id {
        custom_id.as_str()
    } else {
        "local"
    };

    let logger = &DebugLogger {
        id: format!("blueprint-manager-{}", logger_id),
    };

    let logger_clone = logger.clone();

    let keystore = keystore_from_base_path(
        &gadget_config.base_path,
        gadget_config.chain,
        gadget_config.keystore_password.clone(),
    );

    // TODO: Ensure the sr25519 key below is equivalent to the keystore one for symmetricity
    let sr25519_private_key_bytes = node_key_to_bytes(
        gadget_config
            .node_key
            .clone()
            .unwrap_or_else(|| hex::encode(defaults::generate_node_key())),
    )?;
    let sr25519_private_key = sr25519::Keypair::from_secret_key(sr25519_private_key_bytes)
        .map_err(|err| Report::msg(format!("Failed to create SR25519 keypair: {err:?}")))?;

    let (role_key, acco_key) = load_keys_from_keystore(&keystore)?;
    let ecdsa_key = role_key.clone();

    let sub_account_id = AccountId32(acco_key.public().0);
    let subxt_config = SubxtConfig {
        endpoint: gadget_config.url.clone(),
    };

    let tangle_environment = TangleEnvironment::new(subxt_config, acco_key, logger.clone());

    let tangle_runtime = tangle_environment.setup_runtime().await?;
    let runtime = ServicesClient::new(logger.clone(), tangle_runtime.client());
    let mut active_shells = HashMap::new();

    // With the basics setup, we must now implement the main logic
    /*
       * Query to get Vec<RpcServicesWithBlueprint>
       * For each RpcServicesWithBlueprint, fetch the associated gadget binary (fetch/download)
        -> If the services field is empty, just emit and log inside the executed binary "that states a new service instance got created by one of these blueprints"
        -> If the services field is not empty, for each service in RpcServicesWithBlueprint.services, spawn the gadget binary, using params to set the job type to listen to (in terms of our old language, each spawned service represents a single "RoleType")
    */

    let (mut operator_subscribed_blueprints, init_event) =
        if let Some(event) = tangle_runtime.next_event().await {
            (
                utils::get_blueprints(&runtime, event.hash, sub_account_id.clone()).await?,
                event,
            )
        } else {
            return Err(Report::msg("Failed to get initial block hash"));
        };

    logger.info(format!(
        "Received {} initial blueprints this operator is registered to",
        operator_subscribed_blueprints.len()
    ));

    event_handler::maybe_handle_state_update(
        &init_event,
        &operator_subscribed_blueprints,
        logger,
        &gadget_config,
        &blueprint_manager_config,
        &mut active_shells,
    )
    .await?;

    let logger_manager = logger.clone();
    let manager_task = async move {
        // Step 2: Listen to FinalityNotifications and poll for new/deleted services that correspond to the blueprints above
        while let Some(event) = tangle_runtime.next_event().await {
            // Check for any events to see if we require an update to our list of operator-subscribed blueprints
            let needs_update = event_handler::check_blueprint_events(
                &event,
                &logger_manager,
                &mut active_shells,
                &sub_account_id,
            )
            .await;

            if needs_update {
                logger_manager.info("Updating the list of operator-subscribed blueprints");
                operator_subscribed_blueprints =
                    utils::get_blueprints(&runtime, event.hash, sub_account_id.clone()).await?;
            }

            // With the synchronization, we can now handle the tangle event again, but with a focus on ensuring that
            // everything that needs to be downloaded/executed is done so, and that everything that does not need to be
            // is not.
            event_handler::maybe_handle_state_update(
                &event,
                &operator_subscribed_blueprints,
                &logger_manager,
                &gadget_config,
                &blueprint_manager_config,
                &mut active_shells,
            )
            .await?;
        }

        Err::<(), _>(utils::msg_to_error("Finality Notification stream died"))
    };

    let (tx_stop, rx_stop) = tokio::sync::oneshot::channel::<()>();

    let logger = logger.clone();
    let shutdown_task = async move {
        tokio::select! {
            _res0 = shutdown_cmd => {
                logger.info("Shutdown-1 command received, closing application");
            },

            _res1 = rx_stop => {
                logger.info("Manual shutdown signal received, closing application");
            }
        }
    };

    let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();

    let combined_task = async move {
        start_rx
            .await
            .map_err(|_err| Report::msg("Failed to receive start signal"))?;

        tokio::select! {
            res0 = manager_task => {
                Err(Report::msg(format!("Blueprint Manager Closed Unexpectedly: {res0:?}")))
            },

            _ = shutdown_task => {
                Ok(())
            }
        }
    };

    let handle = tokio::spawn(combined_task);

    let handle = BlueprintManagerHandle {
        start_tx: Some(start_tx),
        shutdown_call: Some(tx_stop),
        process: handle,
        logger: logger_clone,
        sr25519_id: sr25519_private_key,
        ecdsa_id: ecdsa_key,
    };

    Ok(handle)
}
