// This file is part of Tangle.
// Copyright (C) 2022-2023 Webb Technologies Inc.
//
// Tangle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Tangle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Tangle.  If not, see <http://www.gnu.org/licenses/>.

#![allow(clippy::async_yields_async)]
use crate::PerTestNodeInput;
use alloy_primitives::hex;
use futures::StreamExt;
use blueprint_manager::executor::BlueprintManagerHandle;
use blueprint_manager::sdk::entry::SendFuture;
use cargo_tangle::deploy::{Opts, PrivateKeySigner};
use gadget_sdk::clients::tangle::runtime::TangleClient;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::PriceTargets;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::calls::types::register::{Preferences, RegistrationArgs};
use libp2p::Multiaddr;
use log::debug;
use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use futures::stream::FuturesOrdered;
use url::Url;
use std::path::PathBuf;
use subxt::tx::Signer;
use gadget_sdk::keystore::KeystoreUriSanitizer;
use sp_core::Pair;
use tracing::Instrument;
use gadget_io::SupportedChains;
use gadget_sdk::{error, info, warn};
use gadget_sdk::clients::tangle::services::{RpcServicesWithBlueprint, ServicesClient};
use gadget_sdk::config::{ContextConfig, GadgetConfiguration};
use gadget_sdk::runners::BlueprintRunner;
use gadget_sdk::runners::tangle::TangleConfig;
use gadget_sdk::subxt_core::config::Header;
use gadget_sdk::utils::test_utils::get_client;
use crate::tangle::transactions;

const LOCAL_BIND_ADDR: &str = "127.0.0.1";
pub const NAME_IDS: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];

/// Initialize network configuration for test nodes
fn initialize_network_config(n: usize) -> Vec<(Multiaddr, u16)> {
    assert!(n > 0, "At least one node is required");
    assert!(n <= NAME_IDS.len(), "Only up to 5 nodes are supported");

    let bind_addrs = (0..n)
        .map(|_| find_open_tcp_bind_port())
        .map(|port| {
            (
                Multiaddr::from_str(&format!("/ip4/{LOCAL_BIND_ADDR}/tcp/{port}"))
                    .expect("Should parse MultiAddr"),
                port,
            )
        })
        .collect::<Vec<_>>();

    // Sanity check: ensure uniqueness
    assert_eq!(
        bind_addrs.iter().map(|r| r.1).collect::<HashSet<_>>().len(),
        bind_addrs.len()
    );

    bind_addrs
}

/// Initialize blueprint manager handles for each test node
async fn initialize_handles<
    D: Send + Clone + 'static,
    F: Fn(PerTestNodeInput<D>) -> Fut,
    Fut: SendFuture<'static, BlueprintManagerHandle>,
>(
    bind_addrs: &[(Multiaddr, u16)],
    multi_addrs: Vec<Multiaddr>,
    additional_params: D,
    opts: &Opts,
    f: F,
) -> (Vec<BlueprintManagerHandle>, Opts) {
    let mut handles = vec![];
    let mut opts = opts.clone();

    for (node_index, (my_addr, my_port)) in bind_addrs.iter().enumerate() {
        let test_input = PerTestNodeInput {
            instance_id: node_index as _,
            bind_ip: IpAddr::from_str(LOCAL_BIND_ADDR).expect("Should be a valid IP"),
            bind_port: *my_port,
            bootnodes: multi_addrs
                .iter()
                .filter(|addr| *addr != my_addr)
                .cloned()
                .collect(),
            verbose: 4,
            pretty: false,
            extra_input: additional_params.clone(),
            http_rpc_url: Url::parse(&opts.http_rpc_url).expect("Should parse URL"),
            ws_rpc_url: Url::parse(&opts.ws_rpc_url).expect("Should parse URL"),
        };

        let handle = f(test_input).await;

        let priv_key = handle
            .ecdsa_id()
            .alloy_key()
            .expect("Should create a private key signer");

        let tg_addr = handle.sr25519_id().account_id();
        let evm_addr = handle.ecdsa_id().account_id();
        info!("Signer TG address: {tg_addr}");
        info!("Signer EVM address: {evm_addr}");
        info!("Signer EVM(alloy) address: {}", priv_key.address());

        if node_index == 0 {
            // Replace the None signer and signer_evm values inside opts with Alice's keys
            opts.signer_evm = Some(priv_key);
            opts.signer = Some(handle.sr25519_id().clone().into_inner());
        }

        handles.push(handle);
    }

    (handles, opts)
}

/// Deploy or retrieve MBSM (Master Blueprint Service Manager)
async fn deploy_or_get_mbsm(
    client: &TangleClient,
    local_tangle_node_ws: &str,
    handle: &BlueprintManagerHandle,
    signer_evm: PrivateKeySigner,
) -> (u64, String) {
    match transactions::get_latest_mbsm_revision(client)
        .await
        .expect("Get latest MBSM revision")
    {
        Some((rev, addr)) => {
            debug!("MBSM is deployed at revision #{rev} at address {addr}");
            (rev, addr.to_string())
        }
        None => {
            let bytecode_hex = include_str!("../tnt-core/MasterBlueprintServiceManager.hex");
            let mut raw_hex = bytecode_hex.replace("0x", "").replace("\n", "");
            if raw_hex.len() % 2 != 0 {
                raw_hex = format!("0{}", raw_hex);
            }
            let bytecode = hex::decode(&raw_hex).expect("valid bytecode in hex format");
            let ev = transactions::deploy_new_mbsm_revision(
                local_tangle_node_ws,
                client,
                handle.sr25519_id(),
                signer_evm,
                &bytecode,
            )
            .await
            .expect("deploy new MBSM revision");
            (ev.revision as u64, ev.address.to_string())
        }
    }
}

/// Register operators to blueprint and approve service
async fn register_and_approve_operators(
    client: &TangleClient,
    handles: Vec<BlueprintManagerHandle>,
    blueprint_id: u64,
) -> Vec<BlueprintManagerHandle> {
    let registration_args = RegistrationArgs::new();
    let mut futures_ordered = FuturesOrdered::new();

    // Register operators
    for handle in handles {
        let client = client.clone();
        let registration_args = registration_args.clone();

        let task = async move {
            let keypair = handle.sr25519_id().clone();
            let key = handle.ecdsa_id().signer().public().0;

            let preferences = Preferences {
                key,
                price_targets: PriceTargets {
                    cpu: 0,
                    mem: 0,
                    storage_hdd: 0,
                    storage_ssd: 0,
                    storage_nvme: 0,
                },
            };

            if let Err(err) = transactions::join_operators(&client, &keypair).await {
                let _span = handle.span().enter();

                let err_str = format!("{err}");
                if err_str.contains("MultiAssetDelegation::AlreadyOperator") {
                    warn!("{} is already an operator", keypair.account_id());
                } else {
                    error!("Failed to join delegators: {err}");
                    panic!("Failed to join delegators: {err}");
                }
            }

            if let Err(err) = transactions::register_blueprint(
                &client,
                &keypair,
                blueprint_id,
                preferences,
                registration_args.clone(),
                0,
            )
            .await
            {
                error!("Failed to register as operator: {err}");
                panic!("Failed to register as operator: {err}");
            }

            handle
        };

        futures_ordered.push_back(task);
    }

    let handles = futures_ordered
        .collect::<Vec<BlueprintManagerHandle>>()
        .await;

    // Request service
    let all_nodes = handles
        .iter()
        .map(|handle| handle.sr25519_id().account_id().clone())
        .collect();

    info!("Requesting service for blueprint ID {blueprint_id} using Alice's keys ...");

    if let Err(err) =
        transactions::request_service(client, handles[0].sr25519_id(), blueprint_id, all_nodes, 0)
            .await
    {
        error!("Failed to register service: {err}");
        panic!("Failed to register service: {err}");
    }

    let next_request_id = transactions::get_next_request_id(client)
        .await
        .expect("Failed to get next request ID")
        .saturating_sub(1);

    // Approve service
    let mut futures_ordered = FuturesOrdered::new();

    for handle in handles {
        let client = client.clone();
        let task = async move {
            let keypair = handle.sr25519_id().clone();
            if let Err(err) =
                transactions::approve_service(&client, &keypair, next_request_id, 20).await
            {
                let _span = handle.span().enter();
                error!("Failed to approve service request {next_request_id}: {err}");
                panic!("Failed to approve service request {next_request_id}: {err}");
            }

            handle
        };

        futures_ordered.push_back(task);
    }

    futures_ordered
        .collect::<Vec<BlueprintManagerHandle>>()
        .await
}

/// Start blueprint managers and wait for nodes to be online
async fn start_blueprint_managers(
    mut handles: Vec<BlueprintManagerHandle>,
) -> Vec<BlueprintManagerHandle> {
    for handle in handles.iter_mut() {
        handle.start().expect("Failed to start blueprint manager");
    }

    info!("Waiting for all nodes to be online ...");
    let all_paths = handles
        .iter()
        .map(|r| r.keystore_uri().to_string())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    wait_for_test_ready(all_paths).await;
    info!("All nodes are online");

    handles
}

pub async fn new_test_ext_blueprint_manager<
    const N: usize,
    const K: usize,
    D: Send + Clone + 'static,
    F: Fn(PerTestNodeInput<D>) -> Fut,
    Fut: SendFuture<'static, BlueprintManagerHandle>,
>(
    additional_params: D,
    opts: Opts,
    f: F,
) -> LocalhostTestExt {
    let span = tracing::info_span!("Integration-Test");
    let _span = span.enter();

    // Initialize network configuration
    let bind_addrs = initialize_network_config(N);
    let multi_addrs = bind_addrs
        .iter()
        .map(|(addr, _)| addr.clone())
        .collect::<Vec<_>>();

    // Initialize handles
    let (handles, opts) =
        initialize_handles(&bind_addrs, multi_addrs, additional_params, &opts, f).await;

    let local_tangle_node_ws: Url = opts.ws_rpc_url.clone().parse().unwrap();
    let local_tangle_node_http: Url = opts.http_rpc_url.clone().parse().unwrap();

    let client = get_client(
        &local_tangle_node_ws.as_str(),
        &local_tangle_node_http.as_str(),
    )
    .await
    .expect("Failed to create an account-based localhost client");

    // Deploy or get MBSM
    let (_rev, _addr) = deploy_or_get_mbsm(
        &client,
        &local_tangle_node_ws.as_str(),
        &handles[0],
        opts.signer_evm.clone().expect("Signer EVM is set"),
    )
    .await;

    // Create blueprint using Alice's identity
    let blueprint_id = match cargo_tangle::deploy::deploy_to_tangle(opts.clone()).await {
        Ok(id) => id,
        Err(err) => {
            error!("Failed to deploy blueprint: {err}");
            panic!("Failed to deploy blueprint: {err}");
        }
    };

    // // Use the default Tangle Config
    // let tangle_config = TangleConfig::default();
    // let keystore = "file::memory:".to_string();
    //
    // let config = ContextConfig::create_tangle_config(
    //     local_tangle_node_http,
    //     local_tangle_node_ws,
    //     keystore,
    //     SupportedChains::LocalTestnet,
    // );
    // let gadget_config = gadget_sdk::config::load(config).expect("Failed to load environment");
    //
    // for _handle in &handles {
    //     let mut runner = BlueprintRunner::new(tangle_config.clone(), gadget_config.clone());
    //
    //     // TODO: Add any jobs or background services for each handle
    //     // runner.job(...);
    //     // runner.background_service(...);
    //
    //     tokio::spawn(async move {
    //         if let Err(e) = runner.run().await {
    //             error!("Runner error: {:?}", e);
    //         }
    //     });
    // }

    // Get blueprint information
    let now = client
        .blocks()
        .at_latest()
        .await
        .expect("Unable to get block")
        .header()
        .hash()
        .0;
    let services_client = ServicesClient::new(client.clone());
    let blueprints = services_client
        .query_operator_blueprints(now, handles[0].sr25519_id().account_id().clone())
        .await
        .expect("Failed to query operator blueprints");
    assert!(!blueprints.is_empty(), "No blueprints found");

    let blueprint = blueprints
        .into_iter()
        .find(|r| r.blueprint_id == blueprint_id)
        .expect("Blueprint not found in operator's blueprints");

    // Start blueprint managers and wait for nodes to be online
    let handles = start_blueprint_managers(handles).await;

    drop(_span);

    LocalhostTestExt {
        client,
        handles,
        blueprint,
        span,
    }
}

pub fn find_open_tcp_bind_port() -> u16 {
    let listener = std::net::TcpListener::bind(format!("{LOCAL_BIND_ADDR}:0"))
        .expect("Should bind to localhost");
    let port = listener
        .local_addr()
        .expect("Should have a local address")
        .port();
    drop(listener);
    port
}

pub struct LocalhostTestExt {
    client: TangleClient,
    handles: Vec<BlueprintManagerHandle>,
    span: tracing::Span,
    blueprint: RpcServicesWithBlueprint,
}

impl LocalhostTestExt {
    /// An identity function (For future reverse-compatible changes)
    pub fn execute_with<
        T: FnOnce(&TangleClient, &Vec<BlueprintManagerHandle>, &RpcServicesWithBlueprint) -> R
            + Send
            + 'static,
        R: Send + 'static,
    >(
        &self,
        function: T,
    ) -> R {
        let _span = self.span.enter();
        function(&self.client, &self.handles, &self.blueprint)
    }

    /// An identity function (For future reverse-compatible changes)
    pub async fn execute_with_async<
        'a,
        'b: 'a,
        T: FnOnce(
                &'a TangleClient,
                &'a Vec<BlueprintManagerHandle>,
                &'a RpcServicesWithBlueprint,
            ) -> R
            + Send
            + 'a,
        R: Future<Output = Out> + Send + 'a,
        Out: Send + 'b,
    >(
        &'a self,
        function: T,
    ) -> Out {
        function(&self.client, &self.handles, &self.blueprint)
            .instrument(self.span.clone())
            .await
    }
}

/// `base_paths`: All the paths pointing to the keystore for each node
/// This function returns when every test_started.tmp file exists
async fn wait_for_test_ready(base_paths: Vec<PathBuf>) {
    let paths = base_paths
        .into_iter()
        .map(|r| r.join("test_started.tmp"))
        .map(|r| r.sanitize_file_path())
        .collect::<Vec<_>>();
    info!("Waiting for these paths to exist: {paths:?}");
    loop {
        let mut ready_count = 0;
        for path in &paths {
            if path.exists() {
                ready_count += 1;
            }
        }

        if ready_count == paths.len() {
            break;
        }

        info!(
            "Not all operators are ready yet ({ready_count}/{}). Waiting ...",
            paths.len()
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
