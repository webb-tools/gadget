use crate::config::BlueprintManagerConfig;
use crate::gadget;
use crate::gadget::ActiveShells;
use crate::utils::github_fetcher_to_native_github_metadata;
use gadget_common::config::DebugLogger;
use gadget_common::tangle_runtime::AccountId32;
use gadget_io::GadgetConfig;
use std::sync::atomic::Ordering;
use tangle_environment::api::RpcServicesWithBlueprint;
use tangle_environment::gadget::TangleEvent;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::GadgetSourceFetcher;
use tangle_subxt::tangle_testnet_runtime::api::services::events::{
    JobCalled, JobResultSubmitted, Registered, ServiceInitiated, Unregistered,
};

/// Returns true if the blueprint manager needs to update the list of operator-subscribed blueprints
pub(crate) async fn check_blueprint_events(
    event: &TangleEvent,
    logger: &DebugLogger,
    active_shells: &mut ActiveShells,
    account_id: &AccountId32,
) -> bool {
    let registered_events = event.events.find::<Registered>();
    let unregistered_events = event.events.find::<Unregistered>();
    let service_initiated_events = event.events.find::<ServiceInitiated>();
    let job_called_events = event.events.find::<JobCalled>();
    let job_result_submitted_events = event.events.find::<JobResultSubmitted>();

    let mut needs_update = false;

    // Handle blueprint registered events
    for evt in registered_events {
        match evt {
            Ok(evt) => {
                logger.info(format!("Blueprint registered event: {evt:?}"));
                needs_update = true;
            }
            Err(err) => {
                logger.warn(format!("Error handling registered event: {err:?}"));
            }
        }
    }

    // Handle unregistered events
    for evt in unregistered_events {
        match evt {
            Ok(evt) => {
                logger.info(format!("Unregistered event: {evt:?}"));
                if &evt.operator == account_id && active_shells.remove(&evt.blueprint_id).is_some()
                {
                    logger.info(format!(
                        "Removed all services for blueprint_id: {}",
                        evt.blueprint_id,
                    ));

                    needs_update = true;
                }
            }
            Err(err) => {
                logger.warn(format!("Error handling unregistered event: {err:?}"));
            }
        }
    }

    // Handle service initiated events
    for evt in service_initiated_events {
        match evt {
            Ok(evt) => {
                logger.info(format!("Service initiated event: {evt:?}"));
            }
            Err(err) => {
                logger.warn(format!("Error handling service initiated event: {err:?}"));
            }
        }
    }

    // Handle job called events
    for evt in job_called_events {
        match evt {
            Ok(evt) => {
                logger.info(format!("Job called event: {evt:?}"));
            }
            Err(err) => {
                logger.warn(format!("Error handling job called event: {err:?}"));
            }
        }
    }

    // Handle job result submitted events
    for evt in job_result_submitted_events {
        match evt {
            Ok(evt) => {
                logger.info(format!("Job result submitted event: {evt:?}"));
            }
            Err(err) => {
                logger.warn(format!(
                    "Error handling job result submitted event: {err:?}"
                ));
            }
        }
    }

    needs_update
}

pub(crate) async fn maybe_handle_state_update(
    event: &TangleEvent,
    blueprints: &Vec<RpcServicesWithBlueprint>,
    logger: &DebugLogger,
    shell_config: &GadgetConfig,
    shell_manager_opts: &BlueprintManagerConfig,
    active_shells: &mut ActiveShells,
) -> color_eyre::Result<()> {
    logger.info(format!("Received notification {}", event.number));
    // TODO: Refactor into Vec<SourceMetadata<T>> where T: NativeGithubMetadata + [...]
    let mut onchain_services = vec![];
    let mut fetchers = vec![];
    let mut service_ids = vec![];

    for blueprint in blueprints {
        let mut services_for_this_blueprint = vec![];
        if let runtime_types::tangle_primitives::services::Gadget::Native(gadget) =
            &blueprint.blueprint.gadget
        {
            let gadget_source = &gadget.soruces.0[0];
            if let GadgetSourceFetcher::Github(gh) = &gadget_source.fetcher {
                let metadata = github_fetcher_to_native_github_metadata(gh, blueprint.blueprint_id);
                onchain_services.push(metadata);
                fetchers.push(gh);

                for service in &blueprint.services {
                    services_for_this_blueprint.push(service.id);
                }
            } else {
                logger.warn(
                    "Blueprint does not contain a Github fetcher and thus currently unsupported",
                );
            }

            service_ids.push(services_for_this_blueprint);
        } else {
            logger
                .warn("Blueprint does not contain a native gadget and thus currently unsupported");
        }
    }

    logger.trace(format!(
        "OnChain services: {:?}",
        onchain_services
            .iter()
            .map(|r| r.git.clone())
            .collect::<Vec<_>>()
    ));

    // Step 3: Check to see if we need to start any new services
    gadget::native::maybe_handle(
        blueprints,
        &onchain_services,
        &fetchers,
        shell_config,
        shell_manager_opts,
        active_shells,
        logger,
    )
    .await?;

    // Check to see if local is running services that are not on-chain
    let mut to_remove: Vec<(u64, u64)> = vec![];

    // Loop through locally running gadget(s). If the validator no longer needs to
    // run the gadget(s), the process corresponding to the gadget gets killed and dropped
    for (blueprint_id, process_handles) in &mut *active_shells {
        for (service_id, process_handle) in process_handles {
            // TODO: verify logic
            if !onchain_services
                .iter()
                .zip(&service_ids)
                .all(|(r, s)| r.blueprint_id != *blueprint_id && !s.contains(service_id))
            {
                logger.warn(format!(
                    "Killing service that is no longer on-chain: bid={blueprint_id}//sid={service_id}",
                ));
                if let Some(abort_handle) = process_handle.1.take() {
                    if abort_handle.send(()).is_err() {
                        logger.error(format!(
                            "Failed to send abort signal to service: bid={blueprint_id}//sid={service_id}",
                        ));
                    }
                }
                to_remove.push((*blueprint_id, *service_id));
            }
        }
    }

    // Check to see if any process handles have died, triggering a restart later in the loop for that process
    for (blueprint_id, process_handles) in &mut *active_shells {
        for (service_id, process_handle) in process_handles {
            if !process_handle.0.load(Ordering::Relaxed) {
                // By removing any killed processes, we will auto-restart them on the next finality notification if required
                to_remove.push((*blueprint_id, *service_id));
            }
        }
    }

    for (blueprint_id, service_id) in to_remove {
        let mut should_delete_blueprint = false;
        if let Some(shells) = active_shells.get_mut(&blueprint_id) {
            shells.remove(&service_id);
            if shells.is_empty() {
                should_delete_blueprint = true;
            }
        }

        if should_delete_blueprint {
            active_shells.remove(&blueprint_id);
        }
    }

    Ok(())
}
