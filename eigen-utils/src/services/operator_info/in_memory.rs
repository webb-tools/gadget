use alloy_primitives::{Address, FixedBytes, Log, U256};

use alloy_sol_types::SolEvent;

use async_trait::async_trait;
use eigen_contracts::{BlsApkRegistry, RegistryCoordinator};
use std::collections::HashMap;
use std::iter::zip;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::task;

use crate::avs_registry::reader::AvsRegistryChainReaderTrait;
use crate::avs_registry::subscriber::AvsRegistryChainSubscriberTrait;
use crate::avs_registry::AvsRegistryContractManager;
use crate::crypto::bls::{G1Point, G2Point};
use crate::types::{operator_id_from_g1_pubkey, OperatorId, OperatorInfo, OperatorPubkeys, Socket};
use crate::Config;

use super::OperatorInfoServiceTrait;

const DEFAULT_LOG_FILTER_QUERY_BLOCK_RANGE: u64 = 10_000;

#[derive(Clone)]
pub struct OperatorsInfoServiceInMemory<T: Config> {
    log_filter_query_block_range: u64,
    avs_registry_manager: AvsRegistryContractManager<T>,
    query_sender: Sender<Query>,
    pubkey_dict: Arc<Mutex<HashMap<Address, OperatorPubkeys>>>,
    operator_addr_to_id: Arc<Mutex<HashMap<Address, OperatorId>>>,
    socket_dict: Arc<Mutex<HashMap<OperatorId, Socket>>>,
}

pub struct Query {
    pub operator_addr: Address,
    pub resp_sender: oneshot::Sender<Resp>,
}

pub struct Resp {
    pub operator_info: OperatorInfo,
    pub operator_exists: bool,
}

impl<T: Config> OperatorsInfoServiceInMemory<T> {
    pub fn new(
        avs_registry_manager: AvsRegistryContractManager<T>,
        log_filter_query_block_range: Option<u64>,
    ) -> Self {
        let (query_sender, query_receiver) = mpsc::channel(100);
        let log_filter_query_block_range =
            log_filter_query_block_range.unwrap_or(DEFAULT_LOG_FILTER_QUERY_BLOCK_RANGE);

        let service = OperatorsInfoServiceInMemory {
            avs_registry_manager,
            log_filter_query_block_range,
            query_sender,
            pubkey_dict: Arc::new(Mutex::new(HashMap::new())),
            operator_addr_to_id: Arc::new(Mutex::new(HashMap::new())),
            socket_dict: Arc::new(Mutex::new(HashMap::new())),
        };

        service.clone().start_service_in_task(query_receiver);

        service
    }

    pub fn start_service_in_task(self, mut query_receiver: Receiver<Query>) {
        let avs_registry_manager = self.avs_registry_manager.clone();
        let pubkey_dict = self.pubkey_dict.clone();
        let operator_addr_to_id = self.operator_addr_to_id.clone();
        let socket_dict = self.socket_dict.clone();

        task::spawn(async move {
            let mut new_pubkey_registration_stream = avs_registry_manager
                .subscribe_to_new_pubkey_registrations()
                .await
                .unwrap();
            let mut new_socket_registration_stream = avs_registry_manager
                .subscribe_to_operator_socket_updates()
                .await
                .unwrap();

            // Fill the pubkey_dict db with the operators and pubkeys found
            if let Err(e) = query_past_registered_operator_events_and_fill_db::<T>(
                &avs_registry_manager,
                &pubkey_dict,
                &operator_addr_to_id,
                &socket_dict,
                self.log_filter_query_block_range,
            )
            .await
            {
                log::error!("Error querying past registered operator events: {:?}", e);
                panic!("Error querying past registered operator events");
            }

            loop {
                tokio::select! {
                    Some(event) = query_receiver.recv() => {
                        match event {
                            Query {
                                operator_addr,
                                resp_sender,
                            } => {
                                let pubkeys_lock = pubkey_dict.lock().unwrap();
                                let pubkeys = pubkeys_lock.get(&operator_addr).cloned();
                                drop(pubkeys_lock);

                                let operator_id = operator_addr_to_id
                                    .lock()
                                    .unwrap()
                                    .get(&operator_addr)
                                    .cloned();
                                let socket = operator_id
                                    .as_ref()
                                    .and_then(|id| {
                                        let socket_lock = socket_dict.lock().unwrap();
                                        let socket = socket_lock.get(id).cloned();
                                        drop(socket_lock);

                                        socket
                                    });

                                let operator_info = OperatorInfo {
                                    socket: socket.unwrap_or_default(),
                                    pubkeys: pubkeys.clone().unwrap_or_default(),
                                };
                                let operator_exists = pubkeys.is_some();
                                let _ = resp_sender.send(Resp {
                                    operator_info,
                                    operator_exists,
                                });
                            }
                        }
                    }
                    Ok(new_pubkey_registration_event) = new_pubkey_registration_stream.recv() => {
                        let block_number = new_pubkey_registration_event.block_number;
                        let new_pubkey_registration_event: Log<BlsApkRegistry::NewPubkeyRegistration> = BlsApkRegistry::NewPubkeyRegistration::decode_log(&new_pubkey_registration_event.inner, true).unwrap();
                        let operator_addr = new_pubkey_registration_event.operator;
                        let pubkey_g1 = G1Point {
                            x: new_pubkey_registration_event.pubkeyG1.X,
                            y: new_pubkey_registration_event.pubkeyG1.Y,
                        };
                        let pubkey_g2 = G2Point {
                            x: new_pubkey_registration_event.pubkeyG2.X,
                            y: new_pubkey_registration_event.pubkeyG2.Y,
                        };

                        let mut pubkey_dict_lock = pubkey_dict.lock().unwrap();
                        pubkey_dict_lock.insert(operator_addr, OperatorPubkeys {
                            g1_pubkey: pubkey_g1.to_ark_g1(),
                            g2_pubkey: pubkey_g2.to_ark_g2(),
                        });
                        drop(pubkey_dict_lock);

                        let operator_id = FixedBytes::<32>::from(pubkey_g1.x);
                        let mut operator_addr_to_id_lock = operator_addr_to_id.lock().unwrap();
                        operator_addr_to_id_lock.insert(operator_addr, operator_id);
                        drop(operator_addr_to_id_lock);

                        log::debug!(
                            "Added operator pubkeys to pubkey dict from new pubkey registration event. Block: {:?}, Operator Address: {:?}, Operator ID: {:?}, G1 Pubkey: {:?}, G2 Pubkey: {:?}",
                            block_number,
                            operator_addr,
                            operator_id,
                            pubkey_g1.to_bytes(),
                            pubkey_g2.to_bytes(),
                        );
                    }
                    Ok(new_socket_registration_event) = new_socket_registration_stream.recv() => {
                        let new_socket_registration_event = RegistryCoordinator::OperatorSocketUpdate::decode_log(&new_socket_registration_event.inner, true).unwrap();

                        let operator_id = new_socket_registration_event.operatorId;
                        let socket = new_socket_registration_event.socket.clone();

                        log::debug!(
                            "Received new socket registration event. Operator ID: {:?}, Socket: {:?}",
                            operator_id,
                            socket.clone(),
                        );

                        let mut socket_dict_lock = socket_dict.lock().unwrap();
                        socket_dict_lock.insert(operator_id, socket);
                        drop(socket_dict_lock);
                    }
                }
            }
        });
    }
}

pub async fn query_past_registered_operator_events_and_fill_db<T: Config>(
    avs_registry_manager: &AvsRegistryContractManager<T>,
    pubkey_dict: &Arc<Mutex<HashMap<Address, OperatorPubkeys>>>,
    operator_addr_to_id: &Arc<Mutex<HashMap<Address, OperatorId>>>,
    socket_dict: &Arc<Mutex<HashMap<OperatorId, Socket>>>,
    log_filter_query_block_range: u64,
) -> Result<(), String> {
    let already_registered_operator_addrs = avs_registry_manager
        .query_existing_registered_operator_pubkeys(0, 0, log_filter_query_block_range)
        .await
        .map_err(|e| e.to_string())?;
    let sockets_map = avs_registry_manager
        .query_existing_registered_operator_sockets(0, 0, log_filter_query_block_range)
        .await
        .map_err(|e| e.to_string())?;

    let (op_addrs_vec, op_pubkeys_vec) = already_registered_operator_addrs;
    for (operator_addr, operator_pubkeys) in zip(op_addrs_vec, op_pubkeys_vec) {
        let mut pubkey_dict = pubkey_dict.lock().unwrap();
        let mut operator_addr_to_id = operator_addr_to_id.lock().unwrap();
        let operator_id = operator_id_from_g1_pubkey(&G1Point {
            x: U256::from_limbs(operator_pubkeys.g1_pubkey.x.0 .0),
            y: U256::from_limbs(operator_pubkeys.g1_pubkey.y.0 .0),
        });
        pubkey_dict.insert(operator_addr, operator_pubkeys.clone());
        operator_addr_to_id.insert(operator_addr, operator_id);
        log::debug!(
            "Added operator pubkeys to pubkey dict: {:?}",
            operator_pubkeys
        );
    }

    for (operator_id, socket) in sockets_map {
        let mut socket_dict = socket_dict.lock().unwrap();
        socket_dict.insert(operator_id, socket.clone());
        log::debug!("Added socket to socket dict: {:?}", socket);
    }

    Ok(())
}

#[async_trait]
impl<T: Config> OperatorInfoServiceTrait for OperatorsInfoServiceInMemory<T> {
    async fn get_operator_info(
        &self,
        operator_addr: Address,
    ) -> Result<Option<OperatorInfo>, String> {
        let (resp_sender, resp_receiver) = oneshot::channel();
        self.query_sender
            .send(Query {
                operator_addr,
                resp_sender,
            })
            .await
            .map_err(|e| e.to_string())?;

        Ok(resp_receiver.await.ok().map(|resp| resp.operator_info))
    }
}
