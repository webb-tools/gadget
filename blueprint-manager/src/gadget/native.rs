use crate::config::BlueprintManagerConfig;
use crate::gadget::ActiveShells;
use crate::protocols::resolver::NativeGithubMetadata;
use crate::utils;
use crate::utils::get_service_str;
use color_eyre::eyre::OptionExt;
use gadget_common::prelude::DebugLogger;
use gadget_io::GadgetConfig;
use std::fmt::Write;
use tangle_environment::api::RpcServicesWithBlueprint;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::{
    GadgetBinary, GithubFetcher,
};
use tokio::io::AsyncWriteExt;

pub async fn maybe_handle(
    blueprints: &Vec<RpcServicesWithBlueprint>,
    onchain_services: &[NativeGithubMetadata],
    onchain_gh_fetchers: &[&GithubFetcher],
    shell_config: &GadgetConfig,
    shell_manager_opts: &BlueprintManagerConfig,
    active_shells: &mut ActiveShells,
    logger: &DebugLogger,
) -> color_eyre::Result<()> {
    for (gh, fetcher) in onchain_services.iter().zip(onchain_gh_fetchers) {
        let native_github_metadata = NativeGithubMetadata {
            git: gh.git.clone(),
            tag: gh.tag.clone(),
            owner: gh.owner.clone(),
            repo: gh.repo.clone(),
            gadget_binaries: fetcher.binaries.0.clone(),
            blueprint_id: gh.blueprint_id,
        };

        if let Err(err) = handle_github_source(
            blueprints,
            &native_github_metadata,
            shell_config,
            shell_manager_opts,
            fetcher,
            active_shells,
            logger,
        )
        .await
        {
            logger.warn(err)
        }
    }

    Ok(())
}

async fn handle_github_source(
    blueprints: &Vec<RpcServicesWithBlueprint>,
    service: &NativeGithubMetadata,
    shell_config: &GadgetConfig,
    shell_manager_opts: &BlueprintManagerConfig,
    github: &GithubFetcher,
    active_shells: &mut ActiveShells,
    logger: &DebugLogger,
) -> color_eyre::Result<()> {
    let blueprint_id = service.blueprint_id;
    let service_str = get_service_str(service);
    if !active_shells.contains_key(&blueprint_id) {
        // Maybe add in the protocol to the active shells
        let relevant_binary =
            get_gadget_binary(&github.binaries.0).ok_or_eyre("Unable to find matching binary")?;
        let expected_hash = slice_32_to_sha_hex_string(relevant_binary.sha256);

        let current_dir = std::env::current_dir()?;
        let mut binary_download_path =
            format!("{}/protocol-{:?}", current_dir.display(), github.tag);

        if utils::is_windows() {
            binary_download_path += ".exe"
        }

        logger.info(format!("Downloading to {binary_download_path}"));

        // Check if the binary exists, if not download it
        let retrieved_hash =
            if !utils::valid_file_exists(&binary_download_path, &expected_hash).await {
                let url = utils::get_download_url(&service.git, &service.tag);

                let download = reqwest::get(&url)
                    .await
                    .map_err(|err| utils::msg_to_error(err.to_string()))?
                    .bytes()
                    .await
                    .map_err(|err| utils::msg_to_error(err.to_string()))?;
                let retrieved_hash = utils::hash_bytes_to_hex(&download);

                // Write the binary to disk
                let mut file = tokio::fs::File::create(&binary_download_path).await?;
                file.write_all(&download).await?;
                file.flush().await?;
                Some(retrieved_hash)
            } else {
                None
            };

        if let Some(retrieved_hash) = retrieved_hash {
            if retrieved_hash.trim() != expected_hash.trim() {
                logger.error(format!(
                    "Binary hash {} mismatched expected hash of {} for protocol: {}",
                    retrieved_hash, expected_hash, service_str
                ));
                return Ok(());
            }
        }

        if !utils::is_windows() {
            if let Err(err) = utils::chmod_x_file(&binary_download_path).await {
                logger.warn(format!("Failed to chmod +x the binary: {err}"));
            }
        }

        for blueprint in blueprints {
            if blueprint.blueprint_id == blueprint_id {
                for svc in &blueprint.services {
                    let service_id = svc.id;
                    let sub_service_str = format!("{service_str}-{service_id}");
                    // Each spawned binary will effectively run a single "RoleType" in old parlance
                    let arguments = utils::generate_process_arguments(
                        shell_config,
                        shell_manager_opts,
                        blueprint_id,
                        service_id,
                    )?;

                    logger.info(format!("Starting protocol: {sub_service_str}"));

                    // Now that the file is loaded, spawn the process
                    let process_handle = tokio::process::Command::new(&binary_download_path)
                        .kill_on_drop(true)
                        .stdout(std::process::Stdio::inherit()) // Inherit the stdout of this process
                        .stderr(std::process::Stdio::inherit()) // Inherit the stderr of this process
                        .stdin(std::process::Stdio::null())
                        .current_dir(&std::env::current_dir()?)
                        .envs(std::env::vars().collect::<Vec<_>>())
                        .args(arguments)
                        .spawn()?;

                    let (status_handle, abort) = utils::generate_running_process_status_handle(
                        process_handle,
                        logger,
                        &sub_service_str,
                    );

                    active_shells
                        .entry(blueprint_id)
                        .or_default()
                        .insert(service_id, (status_handle, Some(abort)));
                }
            }
        }
    }

    Ok(())
}

fn slice_32_to_sha_hex_string(hash: [u8; 32]) -> String {
    hash.iter().fold(String::new(), |mut acc, byte| {
        write!(&mut acc, "{:02x}", byte).expect("Should be able to write");
        acc
    })
}

fn get_gadget_binary(gadget_binaries: &[GadgetBinary]) -> Option<&GadgetBinary> {
    let os = utils::get_formatted_os_string().to_lowercase();
    let arch = std::env::consts::ARCH.to_lowercase();
    for binary in gadget_binaries {
        let binary_str = format!("{:?}", binary.os).to_lowercase();
        if binary_str.contains(&os) || os.contains(&binary_str) || binary_str == os {
            let mut arch_str = format!("{:?}", binary.arch).to_lowercase();

            if arch_str == "amd" {
                arch_str = "x86".to_string()
            } else if arch_str == "amd64" {
                arch_str = "x86_64".to_string()
            }

            if arch_str == arch {
                return Some(binary);
            }
        }
    }

    None
}
