use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

use alloy_primitives::U256;
use alloy_sol_types::SolType;
use eigen_utils::{
    node_api::tokiort::TokioIo,
    services::{
        avs_registry::AvsRegistryServiceChainCaller,
        bls_aggregation::{
            BlsAggregationService, BlsAggregationServiceResponse, BlsAggregatorService,
        },
        operator_info::OperatorInfoServiceTrait,
    },
    types::{quorum_ids_to_bitmap, QuorumNum, QuorumThresholdPercentage, TaskIndex},
    Config,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{self, Bytes},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use tokio::{
    net::TcpListener,
    sync::{broadcast, RwLock},
    time::interval,
};

use crate::{
    avs::{
        writer::IncredibleSquaringWriter,
        IncredibleSquaringContractManager,
        IncredibleSquaringTaskManager::{self, Task, TaskResponse},
        SetupConfig, SignedTaskResponse,
    },
    get_task_response_digest,
    operator::OperatorError,
};

// Constants
pub const TASK_CHALLENGE_WINDOW_BLOCK: u64 = 100;
pub const BLOCK_TIME_SECONDS: u64 = 12;

pub const QUORUM_THRESHOLD_NUMERATOR: u8 = 100;
pub const QUORUM_THRESHOLD_DENOMINATOR: u8 = 100;
pub const QUERY_FILTER_FROM_BLOCK: u64 = 1;

// We only use a single quorum (quorum 0) for incredible squaring
pub const QUORUM_NUMBERS: &[QuorumNum] = &[QuorumNum(0)];

#[derive(Clone)]
pub struct Aggregator<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    server_ip_port_addr: String,
    incredible_squaring_contract_manager: IncredibleSquaringContractManager<T>,
    bls_aggregation_service: BlsAggregatorService<T, I>,
    // bls_aggregation_responses: Receiver<BlsAggregationServiceResponse>,
    tasks: Arc<RwLock<HashMap<u32, Task>>>,
    task_responses: Arc<RwLock<HashMap<u32, HashMap<U256, TaskResponse>>>>,
}

impl<T, I> Aggregator<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    pub async fn build(
        config: &SetupConfig<T>,
        operator_info_service: I,
        server_ip_port_addr: String,
    ) -> Result<Self, OperatorError> {
        let incredible_squaring_contract_manager = IncredibleSquaringContractManager::build(
            config.registry_coordinator_addr,
            config.operator_state_retriever_addr,
            config.eth_client_http.clone(),
            config.eth_client_ws.clone(),
            config.signer.clone(),
        )
        .await?;
        let avs_chain_caller = AvsRegistryServiceChainCaller::build(
            incredible_squaring_contract_manager.service_manager_addr,
            config.registry_coordinator_addr,
            config.operator_state_retriever_addr,
            config.delegate_manager_addr,
            config.avs_directory_addr,
            config.eth_client_http.clone(),
            config.eth_client_ws.clone(),
            config.signer.clone(),
            operator_info_service,
        )
        .await?;
        let (tx, _) = broadcast::channel(100);
        let bls_aggregation_service = BlsAggregatorService::new(tx, avs_chain_caller);

        Ok(Self {
            server_ip_port_addr,
            incredible_squaring_contract_manager,
            bls_aggregation_service,
            // bls_aggregation_responses: rx,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            task_responses: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Starting aggregator.");
        log::info!("Starting aggregator RPC server.");

        // Start server in a separate task
        let this = self.clone();
        tokio::spawn(async move { this.start_server().await.unwrap() });

        let mut ticker = interval(Duration::from_secs(10));
        log::info!("Aggregator set to send new task every 10 seconds...");
        let mut task_num = 0;

        // Send the first task immediately
        self.send_new_task(U256::from(task_num)).await?;
        task_num += 1;

        let mut receiver = self
            .clone()
            .bls_aggregation_service
            .aggregated_responses_tx
            .subscribe();
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.send_new_task(U256::from(task_num)).await?;
                    task_num += 1;
                }
                bls_agg_service_resp = receiver.recv() => {
                    if let Ok(bls_agg_service_resp) = bls_agg_service_resp {
                        log::info!("Received response from blsAggregationService");
                        let _ = self.send_aggregated_response_to_contract(bls_agg_service_resp).await;
                    }
                }
            }
        }
    }

    async fn send_new_task(&self, num_to_square: U256) -> Result<(), Box<dyn std::error::Error>> {
        log::info!(
            "Aggregator sending new task with number to square: {:?}",
            num_to_square
        );

        let (new_task, task_index): (Task, TaskIndex) = self
            .incredible_squaring_contract_manager
            .send_new_task_number_to_square(
                num_to_square,
                QUORUM_THRESHOLD_NUMERATOR,
                quorum_ids_to_bitmap(QUORUM_NUMBERS),
            )
            .await?;

        self.tasks
            .write()
            .await
            .insert(task_index, new_task.clone());

        let quorum_threshold_percentages =
            vec![QuorumThresholdPercentage(QUORUM_THRESHOLD_NUMERATOR); QUORUM_NUMBERS.len()];
        let task_time_to_expiry =
            Duration::from_secs(TASK_CHALLENGE_WINDOW_BLOCK * BLOCK_TIME_SECONDS);

        self.bls_aggregation_service
            .initialize_new_task(
                task_index,
                new_task.taskCreatedBlock,
                quorum_ids_to_bitmap(QUORUM_NUMBERS),
                quorum_threshold_percentages,
                task_time_to_expiry,
            )
            .await;

        Ok(())
    }

    async fn send_aggregated_response_to_contract(
        &self,
        bls_agg_service_resp: BlsAggregationServiceResponse,
    ) {
        if let Some(err) = bls_agg_service_resp.err {
            log::error!("BlsAggregationServiceResponse contains an error: {}", err);
            return;
        }

        let non_signer_pubkeys = bls_agg_service_resp
            .non_signers_pubkeys_g1
            .into_iter()
            .map(|pubkey| IncredibleSquaringTaskManager::G1Point {
                X: pubkey.x,
                Y: pubkey.y,
            })
            .collect();

        let quorum_apks = bls_agg_service_resp
            .quorum_apks_g1
            .into_iter()
            .map(|apk| IncredibleSquaringTaskManager::G1Point { X: apk.x, Y: apk.y })
            .collect();

        let non_signer_stakes_and_signature =
            IncredibleSquaringTaskManager::NonSignerStakesAndSignature {
                nonSignerPubkeys: non_signer_pubkeys,
                quorumApks: quorum_apks,
                apkG2: IncredibleSquaringTaskManager::G2Point {
                    X: bls_agg_service_resp.signers_apk_g2.x,
                    Y: bls_agg_service_resp.signers_apk_g2.y,
                },
                sigma: IncredibleSquaringTaskManager::G1Point {
                    X: bls_agg_service_resp.signers_agg_sig_g1.g1_point.x,
                    Y: bls_agg_service_resp.signers_agg_sig_g1.g1_point.y,
                },
                nonSignerQuorumBitmapIndices: bls_agg_service_resp.non_signer_quorum_bitmap_indices,
                quorumApkIndices: bls_agg_service_resp.quorum_apk_indices,
                totalStakeIndices: bls_agg_service_resp.total_stake_indices,
                nonSignerStakeIndices: bls_agg_service_resp.non_signer_stake_indices,
            };

        log::info!(
            "Threshold reached. Sending aggregated response onchain. {}",
            &format!("task_index: {}", bls_agg_service_resp.task_index),
        );

        let task = {
            let tasks = self.tasks.read().await;
            tasks.get(&bls_agg_service_resp.task_index).cloned()
        };

        let task_response = {
            let task_responses = self.task_responses.read().await;
            task_responses
                .get(&bls_agg_service_resp.task_index)
                .and_then(|responses| {
                    responses.get(&bls_agg_service_resp.task_response_digest.into())
                })
                .cloned()
        };

        if let (Some(task), Some(task_response)) = (task, task_response) {
            if let Err(err) = self
                .incredible_squaring_contract_manager
                .send_aggregated_response(task, task_response, non_signer_stakes_and_signature)
                .await
            {
                log::error!("Aggregator failed to respond to task: {}", &err.to_string());
            }
        }
    }

    async fn process_signed_task_response(
        &self,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let body_bytes = req.collect().await?.to_bytes();
        let signed_task_response: SignedTaskResponse = serde_json::from_slice(&body_bytes)?;

        log::info!("Received signed task response: {:?}", signed_task_response);

        let task_response = IncredibleSquaringTaskManager::TaskResponse::abi_decode(
            &signed_task_response.task_response,
            true,
        )?;
        let task_index = task_response.referenceTaskIndex;
        let task_response_digest = get_task_response_digest(&task_response);
        let task_response_digest_u256 = U256::from_le_bytes(task_response_digest.0);

        {
            let mut task_responses = self.task_responses.write().await;
            task_responses
                .entry(task_index)
                .or_insert_with(HashMap::new);
            let task_response_map = task_responses.get_mut(&task_index).unwrap();
            task_response_map
                .entry(task_response_digest_u256)
                .or_insert(task_response);
        }

        self.bls_aggregation_service
            .process_new_signature(
                task_index,
                task_response_digest.to_vec(),
                signed_task_response.bls_signature,
                signed_task_response.operator_id,
            )
            .await?;

        Ok(Response::new(Full::new(Bytes::from(
            "Task response processed successfully",
        ))))
    }

    // async fn start_server(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     let listener = TcpListener::bind(self.server_ip_port_addr.clone())
    //         .await
    //         .unwrap();
    //     log::info!("Starting server at {}", self.server_ip_port_addr);
    //     loop {
    //         let (stream, _) = listener.accept().await.unwrap();
    //         let io = TokioIo::new(stream);
    //         let aggregator = Arc::new(self.clone());
    //         tokio::task::spawn(async move {
    //             if let Err(err) = http1::Builder::new()
    //                 .serve_connection(
    //                     io,
    //                     service_fn(move |req| {
    //                         let aggregator = Arc::clone(&aggregator);
    //                         async move {
    //                             match req.uri().path() {
    //                                 "/process_signed_task_response" => {
    //                                     aggregator.process_signed_task_response(req).await
    //                                 }
    //                                 _ => Ok(Response::new(Full::new(Bytes::from("404 Not Found")))),
    //                             }
    //                         }
    //                     }),
    //                 )
    //                 .await
    //             {
    //                 println!("Error serving connection: {:?}", err);
    //             }
    //         });
    //     }
    // }

    pub async fn start_server(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.server_ip_port_addr).await?;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let this = Arc::new(self.clone());
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let this = Arc::clone(&this);
                            async move { this.router(req).await }
                        }),
                    )
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn router(
        &self,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        match (req.method(), req.uri().path()) {
            (&Method::POST, path) if path == "/process_signed_task_response" => {
                let _ = self.process_signed_task_response(req).await;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(
                        "Task response processed successfully",
                    )))
                    .unwrap())
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap()),
        }
    }
}
