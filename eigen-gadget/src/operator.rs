#![allow(dead_code)]

use alloy_contract::private::Ethereum;
use alloy_primitives::{Address, ChainId, FixedBytes, Signature, B256, U256};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types::Log;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use alloy_transport::BoxTransport;
use async_trait::async_trait;
use eigen_utils::avs_registry::reader::AvsRegistryChainReaderTrait;
use eigen_utils::avs_registry::AvsRegistryContractManager;
use eigen_utils::crypto::bls::KeyPair;
use eigen_utils::el_contracts::ElChainContractManager;
use eigen_utils::node_api::NodeApi;
use eigen_utils::services::operator_info::OperatorInfoServiceTrait;
use eigen_utils::types::{AvsError, OperatorInfo};
use eigen_utils::Config;
use k256::ecdsa::SigningKey;
use log::error;
use prometheus::Registry;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use thiserror::Error;

use crate::aggregator::Aggregator;
use crate::avs::subscriber::IncredibleSquaringSubscriber;
use crate::avs::{
    IncredibleSquaringContractManager, IncredibleSquaringTaskManager, SetupConfig,
    SignedTaskResponse,
};
use crate::get_task_response_digest;
use crate::rpc_client::AggregatorRpcClient;

const AVS_NAME: &str = "incredible-squaring";
const SEM_VER: &str = "0.0.1";

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("Cannot create HTTP ethclient: {0}")]
    HttpEthClientError(String),
    #[error("Cannot create WS ethclient: {0}")]
    WsEthClientError(String),
    #[error("Cannot parse BLS private key: {0}")]
    BlsPrivateKeyError(String),
    #[error("Cannot get chainId: {0}")]
    ChainIdError(String),
    #[error("Error creating AvsWriter: {0}")]
    AvsWriterError(String),
    #[error("Error creating AvsReader: {0}")]
    AvsReaderError(String),
    #[error("Error creating AvsSubscriber: {0}")]
    AvsSubscriberError(String),
    #[error("Cannot create AggregatorRpcClient: {0}")]
    AggregatorRpcClientError(String),
    #[error("Cannot get operator id: {0}")]
    OperatorIdError(String),
    #[error(
        "Operator is not registered. Register using the operator-cli before starting operator."
    )]
    OperatorNotRegistered,
    #[error("Error in metrics server: {0}")]
    MetricsServerError(String),
    #[error("Error in websocket subscription: {0}")]
    WebsocketSubscriptionError(String),
    #[error("Error getting task response header hash: {0}")]
    TaskResponseHeaderHashError(String),
    #[error("AVS SDK error")]
    AvsSdkError(#[from] AvsError),
    #[error("Wallet error")]
    WalletError(#[from] alloy_signer_local::LocalSignerError),
    #[error("Node API error: {0}")]
    NodeApiError(String),
}

pub struct Operator<T: Config, I: OperatorInfoServiceTrait> {
    config: NodeConfig,
    // metrics_reg: Registry,
    // metrics: Metrics,
    node_api: NodeApi,
    avs_registry_contract_manager: AvsRegistryContractManager<T>,
    incredible_squaring_contract_manager: IncredibleSquaringContractManager<T>,
    eigenlayer_contract_manager: ElChainContractManager<T>,
    bls_keypair: KeyPair,
    operator_id: FixedBytes<32>,
    operator_addr: Address,
    aggregator_server_ip_port_addr: String,
    aggregator_server: Aggregator<T, I>,
    aggregator_rpc_client: AggregatorRpcClient,
}

#[derive(Clone)]
pub struct EigenGadgetProvider {
    pub provider: RootProvider<BoxTransport, Ethereum>,
}

impl Provider for EigenGadgetProvider {
    fn root(&self) -> &RootProvider<BoxTransport, Ethereum> {
        println!("Provider Root TEST");
        &self.provider
    }
}

#[derive(Clone)]
pub struct EigenGadgetSigner {
    pub signer: PrivateKeySigner,
}

impl alloy_signer::Signer for EigenGadgetSigner {
    fn sign_hash<'life0, 'life1, 'async_trait>(
        &'life0 self,
        hash: &'life1 B256,
    ) -> Pin<Box<dyn Future<Output = alloy_signer::Result<Signature>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let signer = self.signer.clone();

        let signature_future = async move { signer.sign_hash(hash).await };

        Box::pin(signature_future)
    }

    fn address(&self) -> Address {
        println!("ADDRESS TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }

    fn chain_id(&self) -> Option<ChainId> {
        println!("CHAIN ID TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }

    fn set_chain_id(&mut self, _chain_id: Option<ChainId>) {
        println!("SET CHAIN ID TEST");
        panic!("Signer functions for EigenGadgetSigner are not yet implemented")
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_api_ip_port_address: String,
    pub enable_node_api: bool,
    pub eth_rpc_url: String,
    pub eth_ws_url: String,
    pub bls_private_key_store_path: String,
    pub ecdsa_private_key_store_path: String,
    pub incredible_squaring_service_manager_addr: String,
    pub avs_registry_coordinator_addr: String,
    pub operator_state_retriever_addr: String,
    pub delegation_manager_addr: String,
    pub avs_directory_addr: String,
    pub eigen_metrics_ip_port_address: String,
    pub server_ip_port_address: String,
    pub operator_address: String,
    pub enable_metrics: bool,
}

impl Config for NodeConfig {
    type TH = BoxTransport;
    type TW = BoxTransport;
    type PH = EigenGadgetProvider;
    type PW = EigenGadgetProvider;
    type S = EigenGadgetSigner;
}

#[derive(Debug, Clone)]
pub struct OperatorInfoService {}

#[async_trait]
impl OperatorInfoServiceTrait for OperatorInfoService {
    async fn get_operator_info(&self, _operator: Address) -> Result<Option<OperatorInfo>, String> {
        todo!()
    }
}

impl<T: Config, I: OperatorInfoServiceTrait> Operator<T, I> {
    pub async fn new_from_config(
        config: NodeConfig,
        eth_client_http: T::PH,
        eth_client_ws: T::PW,
        operator_info_service: I,
        signer: T::S,
    ) -> Result<Self, OperatorError> {
        let _metrics_reg = Registry::new();
        // let avs_and_eigen_metrics = Metrics::new(AVS_NAME, eigen_metrics, &metrics_reg);

        let node_api = NodeApi::new(AVS_NAME, SEM_VER, &config.node_api_ip_port_address);

        // let eth_rpc_client = ProviderBuilder::default()
        //     .with_recommended_fillers()
        //     .on_http(
        //         Url::parse(&config.eth_rpc_url)
        //             .map_err(|e| OperatorError::HttpEthClientError(e.to_string()))?,
        //     );
        // let eth_ws_client = ProviderBuilder::default()
        //     .with_recommended_fillers()
        //     .on_ws(WsConnect::new(&config.eth_ws_url))
        //     .await
        //     .map_err(|e| AvsError::from(e))?;

        log::info!("About to read BLS key");
        let bls_key_password =
            std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let bls_keypair = KeyPair::read_private_key_from_file(
            &config.bls_private_key_store_path,
            &bls_key_password,
        )
        .map_err(OperatorError::from)?;

        let _chain_id = eth_client_http
            .get_chain_id()
            .await
            .map_err(|e| OperatorError::ChainIdError(e.to_string()))?;
        // TODO: Chain id is not used

        log::info!("About to read ECDSA key");
        let ecdsa_key_password =
            std::env::var("OPERATOR_ECDSA_KEY_PASSWORD").unwrap_or_else(|_| "".to_string());
        let ecdsa_secret_key = eigen_utils::crypto::ecdsa::read_key(
            &config.ecdsa_private_key_store_path,
            &ecdsa_key_password,
        )
        .unwrap();
        let _ecdsa_signing_key = SigningKey::from(&ecdsa_secret_key);
        // TODO: Ecdsa signing key is not used

        let setup_config = SetupConfig::<T> {
            registry_coordinator_addr: Address::from_str(&config.avs_registry_coordinator_addr)
                .unwrap(),
            operator_state_retriever_addr: Address::from_str(&config.operator_state_retriever_addr)
                .unwrap(),
            delegate_manager_addr: Address::from_str(&config.delegation_manager_addr).unwrap(),
            avs_directory_addr: Address::from_str(&config.avs_directory_addr).unwrap(),
            eth_client_http: eth_client_http.clone(),
            eth_client_ws: eth_client_ws.clone(),
            signer: signer.clone(),
        };

        let incredible_squaring_contract_manager = IncredibleSquaringContractManager::build(
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .unwrap();

        log::info!("About to build AVS Registry Contract Manager");
        let avs_registry_contract_manager = AvsRegistryContractManager::build(
            Address::from_str(&config.incredible_squaring_service_manager_addr).unwrap(),
            setup_config.registry_coordinator_addr,
            setup_config.operator_state_retriever_addr,
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .unwrap();

        log::info!("About to build aggregator service");
        let aggregator_service = Aggregator::build(
            &setup_config,
            operator_info_service,
            config.server_ip_port_address.clone(),
        )
        .await
        .unwrap();

        log::info!("About to build aggregator RPC client");
        let aggregator_rpc_client = AggregatorRpcClient::new(config.server_ip_port_address.clone());

        log::info!("About to build eigenlayer contract manager");
        let eigenlayer_contract_manager = ElChainContractManager::build(
            setup_config.delegate_manager_addr,
            setup_config.avs_directory_addr,
            eth_client_http.clone(),
            eth_client_ws.clone(),
            signer.clone(),
        )
        .await
        .unwrap();

        log::info!("About to get operator id and address");
        let operator_addr = Address::from_str(&config.operator_address).unwrap();
        let operator_id = avs_registry_contract_manager
            .get_operator_id(operator_addr)
            .await?;

        log::info!(
            "Operator info: operatorId={}, operatorAddr={}, operatorG1Pubkey={:?}, operatorG2Pubkey={:?}",
            hex::encode(operator_id),
            config.operator_address,
            bls_keypair.clone().get_pub_key_g1(),
            bls_keypair.clone().get_pub_key_g2(),
        );

        log::info!("About to create operator");
        let operator = Operator {
            config: config.clone(),
            node_api,
            avs_registry_contract_manager,
            incredible_squaring_contract_manager,
            eigenlayer_contract_manager,
            bls_keypair,
            operator_id,
            operator_addr,
            aggregator_server_ip_port_addr: config.server_ip_port_address.clone(),
            aggregator_server: aggregator_service,
            aggregator_rpc_client,
        };

        // if config.register_operator_on_startup {
        //     operator.register_operator_on_startup(
        //         operator_ecdsa_private_key,
        //         config.token_strategy_addr.parse()?,
        //     );
        // }

        Ok(operator)
    }

    pub async fn start(self) -> Result<(), OperatorError> {
        log::info!("Starting operator.");
        let operator_is_registered = self
            .avs_registry_contract_manager
            .is_operator_registered(self.operator_addr)
            .await; //?;
                    // if !operator_is_registered {
                    //     return Err(OperatorError::OperatorNotRegistered);
                    // }
        log::info!("Operator registration status: {:?}", operator_is_registered);

        if self.config.enable_node_api {
            if let Err(e) = self.node_api.start().await {
                return Err(OperatorError::NodeApiError(e.to_string()));
            }
        }

        let mut sub = self
            .incredible_squaring_contract_manager
            .subscribe_to_new_tasks()
            .await
            .unwrap();

        log::info!("Subscribed to new tasks: {:?}", sub);

        let value = sub.recv().await.unwrap();
        log::info!("Received new task: {:?}", value);

        loop {
            log::info!("About to wait for a new task submissions");
            tokio::select! {
                Ok(new_task_created_log) = sub.recv() => {
                    log::info!("Received new task: {:?}", new_task_created_log);
                    // self.metrics.inc_num_tasks_received();
                    let log: Log<IncredibleSquaringTaskManager::NewTaskCreated> = new_task_created_log.log_decode().unwrap();
                    let task_response = self.process_new_task_created_log(&log);
                    if let Ok(signed_task_response) = self.sign_task_response(&task_response) {
                        let agg_rpc_client = self.aggregator_rpc_client.clone();
                        tokio::spawn(async move {
                            agg_rpc_client.send_signed_task_response_to_aggregator(signed_task_response).await;
                        });
                    }
                },
            }
        }
    }

    fn process_new_task_created_log(
        &self,
        new_task_created_log: &Log<IncredibleSquaringTaskManager::NewTaskCreated>,
    ) -> IncredibleSquaringTaskManager::TaskResponse {
        log::debug!("Received new task: {:?}", new_task_created_log);
        log::info!("Received new task: numberToBeSquared={}, taskIndex={}, taskCreatedBlock={}, quorumNumbers={}, QuorumThresholdPercentage={}",
            new_task_created_log.inner.task.numberToBeSquared,
            new_task_created_log.inner.taskIndex,
            new_task_created_log.inner.task.taskCreatedBlock,
            new_task_created_log.inner.task.quorumNumbers,
            new_task_created_log.inner.task.quorumThresholdPercentage
        );
        let number_squared = new_task_created_log
            .inner
            .task
            .numberToBeSquared
            .pow(U256::from(2));
        IncredibleSquaringTaskManager::TaskResponse {
            referenceTaskIndex: new_task_created_log.inner.taskIndex,
            numberSquared: number_squared,
        }
    }

    fn sign_task_response(
        &self,
        task_response: &IncredibleSquaringTaskManager::TaskResponse,
    ) -> Result<SignedTaskResponse, OperatorError> {
        let task_response_hash = get_task_response_digest(task_response);
        let bls_signature = self.bls_keypair.sign_message(&task_response_hash);
        let signed_task_response = SignedTaskResponse {
            task_response: task_response.abi_encode(),
            bls_signature,
            operator_id: self.operator_id,
        };
        log::debug!("Signed task response: {:?}", signed_task_response);
        Ok(signed_task_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::ProviderBuilder;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_transport_ws::WsConnect;
    use avs::IncredibleSquaringServiceManager;
    use eigen_contracts::*;
    use gadget_common::subxt_signer::bip39::rand_core::OsRng;
    use k256::ecdsa::VerifyingKey;
    use k256::elliptic_curve::SecretKey;

    static BLS_PASSWORD: &str = "BLS_PASSWORD";
    static ECDSA_PASSWORD: &str = "ECDSA_PASSWORD";

    // --------- IMPORTS FOR ANVIL TEST ---------
    // use alloy::signers::Signer;
    use alloy_primitives::{address, Address, Bytes, U256};
    // use alloy_provider::network::{TransactionBuilder, TxSigner};
    use crate::avs;
    use alloy_provider::Provider;
    use alloy_rpc_types_eth::BlockId;
    use anvil::spawn;
    struct ContractAddresses {
        pub service_manager: Address,
        pub registry_coordinator: Address,
        pub operator_state_retriever: Address,
        pub delegation_manager: Address,
        pub avs_directory: Address,
        pub operator: Address,
    }

    async fn run_anvil_testnet() -> ContractAddresses {
        // Initialize the logger
        env_logger::init();

        let (api, mut handle) = spawn(anvil::NodeConfig::test().with_port(33125)).await;
        api.anvil_auto_impersonate_account(true).await.unwrap();
        let provider = handle.http_provider();

        let accounts = handle.dev_wallets().collect::<Vec<_>>();
        let from = accounts[0].address();
        let _to = accounts[1].address();

        let _amount = handle
            .genesis_balance()
            .checked_div(U256::from(2u64))
            .unwrap();

        let _gas_price = provider.get_gas_price().await.unwrap();

        let delegation_manager_addr =
            Address::from(address!("0165878a594ca255338adfa4d48449f69242eb8f"));
        let service_manager_addr =
            Address::from(address!("610178da211fef7d417bc0e6fed39f05609ad788"));
        let stake_registry_addr =
            Address::from(address!("cf7ed3acca5a467e9e704c703e8d87f634fb0fc9"));
        let bls_apk_registry_addr =
            Address::from(address!("9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"));
        let index_registry_addr =
            Address::from(address!("e7f1725e7734ce288f8367e1bb143e90bb3f0512"));
        let strategy_manager_addr =
            Address::from(address!("8fbdb2318678afecb368f032d93f642f64180aa6"));

        let registry_coordinator = RegistryCoordinator::deploy(
            provider.clone(),
            service_manager_addr,
            stake_registry_addr,
            bls_apk_registry_addr,
            index_registry_addr,
        )
        .await
        .unwrap();
        let registry_coordinator_addr = registry_coordinator.address();
        println!("Registry Coordinator returned");
        api.mine_one().await;
        println!(
            "Registry Coordinator deployed at: {:?}",
            registry_coordinator_addr
        );

        let mut index_registry = IndexRegistry::deploy(provider.clone()).await.unwrap();
        let index_registry_addr = index_registry.address();
        println!("Index Registry returned");
        api.mine_one().await;
        println!("Index Registry deployed at: {:?}", index_registry_addr);

        let mut bls_apk_registry =
            BlsApkRegistry::deploy(provider.clone(), *registry_coordinator_addr)
                .await
                .unwrap();
        let bls_apk_registry_addr = bls_apk_registry.address();
        println!("BLS APK Registry returned");
        api.mine_one().await;
        println!("BLS APK Registry deployed at: {:?}", bls_apk_registry_addr);

        let mut stake_registry = StakeRegistry::deploy(
            provider.clone(),
            *registry_coordinator_addr,
            delegation_manager_addr,
        )
        .await
        .unwrap();
        let stake_registry_addr = stake_registry.address();
        println!("Stake Registry returned");
        api.mine_one().await;
        println!("Stake Registry deployed at: {:?}", stake_registry_addr);

        let slasher = ISlasher::deploy(provider.clone()).await.unwrap();
        let slasher_addr = slasher.address();
        println!("Slasher deployed at: {:?}", slasher_addr);

        let eigen_pod_manager = EigenPodManager::deploy(
            provider.clone(),
            Address::from(address!("73e42f117e8643cc03a4197c6c3ab38d8e5bd281")),
            Address::from(address!("83e42f117e8643cc01741973ac7cb3ad8e5bd282")),
            strategy_manager_addr,
            *slasher_addr,
            delegation_manager_addr,
        )
        .await
        .unwrap();
        let eigen_pod_manager_addr = eigen_pod_manager.address();
        println!(
            "Eigen Pod Manager deployed at: {:?}",
            eigen_pod_manager_addr
        );

        let mut delegation_manager = DelegationManager::deploy(
            provider.clone(),
            strategy_manager_addr,
            *slasher_addr,
            *eigen_pod_manager_addr,
        )
        .await
        .unwrap();
        let delegation_manager_addr = delegation_manager.address();
        println!("Delegation Manager returned");
        api.mine_one().await;
        println!(
            "Delegation Manager deployed at: {:?}",
            delegation_manager_addr
        );

        let avs_directory = AVSDirectory::deploy(provider.clone(), delegation_manager_addr.clone())
            .await
            .unwrap();
        let avs_directory_addr = avs_directory.address();
        println!("AVS Directory returned");
        api.mine_one().await;
        println!("AVS Directory deployed at: {:?}", avs_directory_addr);

        let state_retriever = OperatorStateRetriever::deploy(provider.clone())
            .await
            .unwrap();
        let state_retriever_addr = state_retriever.address();
        println!("Operator State Retriever returned");
        api.mine_one().await;
        println!(
            "Operator State Retriever deployed at: {:?}",
            state_retriever_addr
        );

        let task_manager = IncredibleSquaringTaskManager::deploy(
            provider.clone(),
            *registry_coordinator_addr,
            10u32,
        )
        .await
        .unwrap();
        let task_manager_addr = task_manager.address();
        println!("Incredible Squaring Task Manager returned");
        api.mine_one().await;
        println!(
            "Incredible Squaring Task Manager deployed at: {:?}",
            task_manager_addr
        );

        let result = task_manager
            .createNewTask(U256::from(2), 100u32, Bytes::from("0"))
            .call()
            .await
            .unwrap();

        let service_manager = IncredibleSquaringServiceManager::deploy(
            provider.clone(),
            *avs_directory_addr,
            *registry_coordinator_addr,
            *stake_registry_addr,
            *task_manager_addr,
        )
        .await
        .unwrap();
        let service_manager_addr = service_manager.address();
        println!("Incredible Squaring Service Manager returned");
        api.mine_one().await;
        println!(
            "Incredible Squaring Service Manager deployed at: {:?}",
            service_manager_addr
        );

        let _block = provider
            .get_block(BlockId::latest(), false.into())
            .await
            .unwrap()
            .unwrap();

        api.anvil_set_auto_mine(true).await.unwrap();
        let run_testnet = async move {
            let serv = handle.servers.pop().unwrap();
            let res = serv.await.unwrap();
            res.unwrap();
        };
        let spawner_task_manager_address = task_manager_addr.clone();
        let spawner_provider = provider.clone();
        let task_spawner = async move {
            let manager = IncredibleSquaringTaskManager::new(
                spawner_task_manager_address,
                spawner_provider.clone(),
            );
            loop {
                log::info!("About to create new task");
                tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
                let result = manager
                    .createNewTask(U256::from(2), 100u32, Bytes::from("0"))
                    .call()
                    .await
                    .unwrap();
                log::info!("Created new task: {:?}", result);
            }
        };
        tokio::spawn(run_testnet);
        tokio::spawn(task_spawner);
        ContractAddresses {
            service_manager: *service_manager_addr,
            registry_coordinator: *registry_coordinator_addr,
            operator_state_retriever: *state_retriever_addr,
            delegation_manager: *delegation_manager_addr,
            avs_directory: *avs_directory_addr,
            operator: from,
        }
    }

    #[tokio::test]
    async fn test_anvil() {
        let contract_addresses = run_anvil_testnet().await;

        let http_endpoint = "http://127.0.0.1:33125";
        let ws_endpoint = "ws://127.0.0.1:33125";
        let node_config = NodeConfig {
            node_api_ip_port_address: "127.0.0.1:9808".to_string(),
            eth_rpc_url: http_endpoint.to_string(),
            eth_ws_url: ws_endpoint.to_string(),
            bls_private_key_store_path: "./keystore/bls".to_string(),
            ecdsa_private_key_store_path: "./keystore/ecdsa".to_string(),
            incredible_squaring_service_manager_addr: contract_addresses
                .service_manager
                .to_string(),
            avs_registry_coordinator_addr: contract_addresses.registry_coordinator.to_string(),
            operator_state_retriever_addr: contract_addresses.operator_state_retriever.to_string(),
            eigen_metrics_ip_port_address: "127.0.0.1:9100".to_string(),
            delegation_manager_addr: contract_addresses.delegation_manager.to_string(),
            avs_directory_addr: contract_addresses.avs_directory.to_string(),
            operator_address: contract_addresses.operator.to_string(),
            enable_metrics: false,
            enable_node_api: false,
            server_ip_port_address: "".to_string(),
        };

        let operator_info_service = OperatorInfoService {};

        let signer = EigenGadgetSigner {
            signer: PrivateKeySigner::random(),
        };

        let http_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(http_endpoint.parse().unwrap())
            .root()
            .clone()
            .boxed();

        println!("About to set up WS Provider");

        let ws_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_ws(WsConnect::new(ws_endpoint))
            .await
            .unwrap()
            .root()
            .clone()
            .boxed();

        println!("About to set up Operator");

        let operator = Operator::<NodeConfig, OperatorInfoService>::new_from_config(
            node_config.clone(),
            EigenGadgetProvider {
                provider: http_provider,
            },
            EigenGadgetProvider {
                provider: ws_provider,
            },
            operator_info_service,
            signer,
        )
        .await
        .unwrap();

        operator.start().await.unwrap();
    }

    #[tokio::test]
    async fn test_generate_keys() {
        env_logger::init();

        // ---------------- BLS ----------------
        let bls_pair = KeyPair::gen_random().unwrap();
        bls_pair
            .save_to_file("./keystore/bls", BLS_PASSWORD)
            .unwrap();
        let bls_keys = KeyPair::read_private_key_from_file("./keystore/bls", BLS_PASSWORD).unwrap();
        assert_eq!(bls_pair.priv_key.key, bls_keys.priv_key.key);
        assert_eq!(bls_pair.pub_key, bls_keys.pub_key);

        //---------------- ECDSA ----------------
        let signing_key = SigningKey::random(&mut OsRng);
        let secret_key = SecretKey::from(signing_key.clone());
        let public_key = secret_key.public_key();
        let verifying_key = VerifyingKey::from(&signing_key);
        eigen_utils::crypto::ecdsa::write_key("./keystore/ecdsa", &secret_key, ECDSA_PASSWORD)
            .unwrap();

        let read_ecdsa_secret_key =
            eigen_utils::crypto::ecdsa::read_key("./keystore/ecdsa", ECDSA_PASSWORD).unwrap();
        let read_ecdsa_public_key = read_ecdsa_secret_key.public_key();
        let read_ecdsa_signing_key = SigningKey::from(&read_ecdsa_secret_key);
        let read_ecdsa_verifying_key = VerifyingKey::from(&read_ecdsa_signing_key);

        assert_eq!(secret_key, read_ecdsa_secret_key);
        assert_eq!(public_key, read_ecdsa_public_key);
        assert_eq!(signing_key, read_ecdsa_signing_key);
        assert_eq!(verifying_key, read_ecdsa_verifying_key);
    }

    #[tokio::test]
    async fn test_run_operator() {
        env_logger::init();
        let http_endpoint = "http://127.0.0.1:33125";
        let ws_endpoint = "ws://127.0.0.1:33125";
        let node_config = NodeConfig {
            node_api_ip_port_address: "127.0.0.1:9808".to_string(),
            eth_rpc_url: http_endpoint.to_string(),
            eth_ws_url: ws_endpoint.to_string(),
            bls_private_key_store_path: "./keystore/bls".to_string(),
            ecdsa_private_key_store_path: "./keystore/ecdsa".to_string(),
            incredible_squaring_service_manager_addr: "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"
                .to_string(),
            avs_registry_coordinator_addr: "0x5fbdb2315678afecb367f032d93f642f64180aa3".to_string(),
            operator_state_retriever_addr: "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9".to_string(),
            eigen_metrics_ip_port_address: "127.0.0.1:9100".to_string(),
            delegation_manager_addr: "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512".to_string(),
            avs_directory_addr: "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0".to_string(),
            operator_address: "0x0000000000000000000000000000000000000006".to_string(),
            enable_metrics: false,
            enable_node_api: false,
            server_ip_port_address: "".to_string(),
        };

        let operator_info_service = OperatorInfoService {};

        let signer = EigenGadgetSigner {
            signer: PrivateKeySigner::random(),
        };

        let http_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(http_endpoint.parse().unwrap())
            .root()
            .clone()
            .boxed();

        println!("About to set up WS Provider");

        let ws_provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_ws(WsConnect::new(ws_endpoint))
            .await
            .unwrap()
            .root()
            .clone()
            .boxed();

        println!("About to set up Operator");

        let operator = Operator::<NodeConfig, OperatorInfoService>::new_from_config(
            node_config.clone(),
            EigenGadgetProvider {
                provider: http_provider,
            },
            EigenGadgetProvider {
                provider: ws_provider,
            },
            operator_info_service,
            signer,
        )
        .await
        .unwrap();

        operator.start().await.unwrap();
    }
}
