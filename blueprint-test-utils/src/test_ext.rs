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

use crate::{get_blueprint_base_dir, read_cargo_toml_file, PerTestNodeInput};
use alloy_primitives::hex;
use futures::StreamExt;
use blueprint_manager::executor::BlueprintManagerHandle;
use blueprint_manager::sdk::entry::SendFuture;
use cargo_tangle::deploy::Opts;
use gadget_sdk::clients::tangle::runtime::TangleClient;
use gadget_sdk::k256::ecdsa::{SigningKey, VerifyingKey};
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::PriceTargets;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::calls::types::register::{Preferences, RegistrationArgs};
use subxt::ext::sp_runtime::traits::IdentifyAccount;
use libp2p::Multiaddr;
use log::debug;
use sp_core::crypto::Ss58AddressFormat;
use subxt::ext::sp_runtime::traits::Verify;
use subxt::ext::sp_runtime::MultiSignature;
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
use sp_core::{sr25519, Pair, Public};
use tracing::Instrument;
use gadget_sdk::{error, info, warn};
use gadget_sdk::clients::tangle::services::{RpcServicesWithBlueprint, ServicesClient};
use gadget_sdk::subxt_core::config::Header;
use gadget_sdk::utils::test_utils::get_client;
use crate::tangle::node::SubstrateNode;
use crate::tangle::{transactions, NodeConfig};
use tnt_core_bytecode::bytecode::MASTER_BLUEPRINT_SERVICE_MANAGER;

const LOCAL_BIND_ADDR: &str = "127.0.0.1";
pub const NAME_IDS: [&str; 5] = ["Alice", "Bob", "Charlie", "Dave", "Eve"];

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> TPublic::Pair {
    TPublic::Pair::from_string(&format!("//{seed}"), None).expect("static values are valid; qed")
}

/// - `N`: number of nodes
/// - `K`: Number of networks accessible per node (should be equal to the number of services in a given blueprint)
/// - `D`: Any data that you want to pass with NodeInput.
/// - `F`: A function that generates a service's execution via a series of shells. Each shell executes a subset of the service,
///        as each service may have a set of operations that are executed in parallel, sequentially, or concurrently.
#[allow(clippy::async_yields_async)]
pub async fn new_test_ext_blueprint_manager<
    const N: usize,
    const K: usize,
    D: Send + Clone + 'static,
    F: Fn(PerTestNodeInput<D>) -> Fut,
    Fut: SendFuture<'static, BlueprintManagerHandle>,
>(
    additional_params: D,
    f: F,
    node_config: NodeConfig,
) -> LocalhostTestExt {
    assert!(N > 0, "At least one node is required");
    assert!(N <= NAME_IDS.len(), "Only up to 5 nodes are supported");

    let span = tracing::info_span!("Integration-Test");
    let _span = span.enter();

    let base_path = get_blueprint_base_dir();
    let base_path = base_path
        .canonicalize()
        .expect("File could not be normalized");

    let manifest_path = base_path.join("Cargo.toml");
    tracing::debug!("Manifest path: {}", manifest_path.display());

    let manifest =
        read_cargo_toml_file(&manifest_path).expect("Failed to read blueprint's Cargo.toml");
    let blueprint_name = manifest.package.as_ref().unwrap().name.clone();

    tracing::info!("Starting Tangle node...");
    let tangle_node = crate::tangle::run(node_config).await.unwrap();
    tracing::info!("Tangle node running on port: {}", tangle_node.ws_port());

    let mut opts = Opts {
        pkg_name: Some(blueprint_name),
        http_rpc_url: format!("http://127.0.0.1:{}", tangle_node.ws_port()),
        ws_rpc_url: format!("ws://127.0.0.1:{}", tangle_node.ws_port()),
        manifest_path,
        signer: None,
        signer_evm: None,
    };

    let bind_addrs = (0..N)
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

    let multi_addrs = bind_addrs
        .iter()
        .map(|(addr, _)| addr.clone())
        .collect::<Vec<_>>();

    let mut handles = vec![];

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
        info!("Signer TG account: {tg_addr}");
        info!("Signer EVM public key: 0x{}", hex::encode(evm_addr.0));
        info!("Signer EVM(alloy) address: {}", priv_key.address());

        if node_index == 0 {
            // Replace the None signer and signer_evm values inside opts with Alice's keys
            opts.signer_evm = Some(priv_key);
            opts.signer = Some(handle.sr25519_id().clone().into_inner());
        }

        handles.push(handle);
    }

    let local_tangle_node_ws = opts.ws_rpc_url.clone();
    let local_tangle_node_http = opts.http_rpc_url.clone();

    let client = get_client(&local_tangle_node_ws, &local_tangle_node_http)
        .await
        .expect("Failed to create an account-based localhost client");

    // Check if the MBSM is already deployed.
    let latest_revision = transactions::get_latest_mbsm_revision(&client)
        .await
        .expect("Get latest MBSM revision");
    match latest_revision {
        Some((rev, addr)) => debug!("MBSM is deployed at revision #{rev} at address {addr}"),
        None => {
            let bytecode = MASTER_BLUEPRINT_SERVICE_MANAGER;
            gadget_sdk::trace!("Using MBSM bytecode of length: {}", bytecode.len());

            let ev = transactions::deploy_new_mbsm_revision(
                &local_tangle_node_ws,
                &client,
                handles[0].sr25519_id(),
                opts.signer_evm.clone().expect("Signer EVM is set"),
                bytecode,
            )
            .await
            .expect("deploy new MBSM revision");
            let rev = ev.revision;
            let addr = ev.address;
            debug!("Deployed MBSM at revision #{rev} at address {addr}");
        }
    };

    // Step 1: Create the blueprint using alice's identity
    let blueprint_id = match cargo_tangle::deploy::deploy_to_tangle(opts.clone()).await {
        Ok(id) => id,
        Err(err) => {
            error!("Failed to deploy blueprint: {err}");
            panic!("Failed to deploy blueprint: {err}");
        }
    };

    // Step 2: Have each identity register to a blueprint
    let mut futures_ordered = FuturesOrdered::new();
    let registration_args = RegistrationArgs::new();
    // TODO: allow the function called to specify the registration args

    for handle in handles {
        let client = client.clone();
        let registration_args = registration_args.clone();

        let task = async move {
            let keypair = handle.sr25519_id().clone();
            let ecdsa_key = handle.ecdsa_id().signer();
            let secret = SigningKey::from_slice(&ecdsa_key.seed())
                .expect("Should be able to create a secret key from a seed");
            let verifying_key = VerifyingKey::from(secret);
            let public_key = verifying_key.to_encoded_point(false);
            let key = public_key.to_bytes().to_vec().try_into().unwrap();
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

    // Step 3: request a service
    let all_nodes = handles
        .iter()
        .map(|handle| handle.sr25519_id().account_id().clone())
        .collect();

    // Use Alice's account to register the service
    info!("Requesting service for blueprint ID {blueprint_id} using Alice's keys ...");

    if let Err(err) =
        transactions::request_service(&client, handles[0].sr25519_id(), blueprint_id, all_nodes, 0)
            .await
    {
        error!("Failed to register service: {err}");
        panic!("Failed to register service: {err}");
    }

    let next_request_id = transactions::get_next_request_id(&client)
        .await
        .expect("Failed to get next request ID")
        .saturating_sub(1);

    // Step 2: Have each identity register to a blueprint
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

    let mut handles = futures_ordered
        .collect::<Vec<BlueprintManagerHandle>>()
        .await;

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

    // Now, start every blueprint manager. With the blueprint submitted and every operator registered
    // to the blueprint, we can now start the blueprint manager, expecting that the blueprint manager
    // will start the services associated with the blueprint as gadgets.
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

    drop(_span);

    LocalhostTestExt {
        _tangle_node: tangle_node,
        client,
        handles,
        span,
        blueprint,
        opts,
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
    // Unused, stored here to keep it from dropping early
    _tangle_node: SubstrateNode,
    client: TangleClient,
    handles: Vec<BlueprintManagerHandle>,
    span: tracing::Span,
    blueprint: RpcServicesWithBlueprint,
    opts: Opts,
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
                &'a Opts,
            ) -> R
            + Send
            + 'a,
        R: Future<Output = Out> + Send + 'a,
        Out: Send + 'b,
    >(
        &'a self,
        function: T,
    ) -> Out {
        function(&self.client, &self.handles, &self.blueprint, &self.opts)
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
