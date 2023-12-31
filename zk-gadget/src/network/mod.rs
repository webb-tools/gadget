use async_trait::async_trait;
use bytes::Bytes;
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::StreamExt;
use gadget_core::job_manager::WorkManagerInterface;
use mpc_net::multi::WrappedStream;
use mpc_net::prod::{CertToDer, RustlsCertificate};
use mpc_net::MpcNetError;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio_rustls::rustls::server::NoClientAuth;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::{rustls, TlsAcceptor, TlsStream};

/// Type should correspond to the on-chain identifier of the registrant
pub type RegistantId = UserID;

#[derive(Clone)]
pub enum ZkNetworkService {
    King {
        listener: Arc<Mutex<Option<tokio::net::TcpListener>>>,
        registrants: Arc<Mutex<HashMap<RegistantId, Registrant>>>,
        to_gadget: UnboundedSender<RegistryPacket>,
        to_outbound_txs: Arc<RwLock<HashMap<RegistantId, UnboundedSender<RegistryPacket>>>>,
        inbound_messages: Arc<Mutex<UnboundedReceiver<RegistryPacket>>>,
        identity: RustlsCertificate,
    },
    Client {
        king_registry_addr: SocketAddr,
        registrant_id: RegistantId,
        cert_der: Vec<u8>,
        local_to_outbound_tx: UnboundedSender<RegistryPacket>,
        inbound_messages: Arc<Mutex<UnboundedReceiver<RegistryPacket>>>,
    },
}

#[allow(dead_code)]
pub struct Registrant {
    id: RegistantId,
    cert_der: Vec<u8>,
}

use crate::Error;
use gadget_common::gadget::message::{GadgetProtocolMessage, UserID};
use gadget_common::gadget::network::Network;
use gadget_common::gadget::work_manager::WebbWorkManager;

pub fn create_server_tls_acceptor<T: CertToDer>(
    server_certificate: T,
) -> Result<TlsAcceptor, MpcNetError> {
    let client_auth = NoClientAuth::boxed();
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(
            vec![rustls::Certificate(
                server_certificate.serialize_certificate_to_der()?,
            )],
            rustls::PrivateKey(server_certificate.serialize_private_key_to_der()?),
        )
        .unwrap();
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

impl ZkNetworkService {
    pub async fn new_king<T: std::net::ToSocketAddrs>(
        bind_addr: T,
        identity: RustlsCertificate,
    ) -> Result<Self, Error> {
        let bind_addr = to_addr(bind_addr)?;

        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|err| Error::RegistryCreateError {
                err: err.to_string(),
            })?;
        let registrants = Arc::new(Mutex::new(HashMap::new()));
        let (to_gadget, from_registry) = tokio::sync::mpsc::unbounded_channel();
        Ok(ZkNetworkService::King {
            listener: Arc::new(Mutex::new(Some(listener))),
            to_outbound_txs: Arc::new(RwLock::new(HashMap::new())),
            registrants,
            to_gadget,
            identity,
            inbound_messages: Arc::new(Mutex::new(from_registry)),
        })
    }

    pub async fn new_client<T: std::net::ToSocketAddrs>(
        king_registry_addr: T,
        registrant_id: RegistantId,
        client_identity: RustlsCertificate,
        king_certs: RootCertStore,
    ) -> Result<Self, Error> {
        let king_registry_addr = to_addr(king_registry_addr)?;
        let cert_der = client_identity.cert.0.clone();

        let connection = TcpStream::connect(king_registry_addr)
            .await
            .map_err(|err| Error::RegistryCreateError {
                err: err.to_string(),
            })?;

        log::info!(
            "Party {registrant_id} connected to king registry at {}",
            king_registry_addr
        );

        // Upgrade to TLS
        let tls = mpc_net::prod::create_client_mutual_tls_connector(king_certs, client_identity)
            .map_err(|err| Error::RegistryCreateError {
                err: format!("{err:?}"),
            })?;

        let connection = tls
            .connect(
                rustls::ServerName::IpAddress(king_registry_addr.ip()),
                connection,
            )
            .await
            .map_err(|err| Error::RegistryCreateError {
                err: err.to_string(),
            })?;

        let (to_gadget, from_registry) = tokio::sync::mpsc::unbounded_channel();
        let (local_to_outbound_tx, local_to_outbound_rx) = tokio::sync::mpsc::unbounded_channel();

        let connection = TlsStream::Client(connection);

        handle_single_connection(connection, local_to_outbound_rx, to_gadget);

        let this = ZkNetworkService::Client {
            king_registry_addr,
            local_to_outbound_tx,
            registrant_id,
            cert_der,
            inbound_messages: Arc::new(Mutex::new(from_registry)),
        };

        this.client_register().await?;

        Ok(this)
    }

    async fn client_register(&self) -> Result<(), Error> {
        match self {
            Self::King { .. } => Err(Error::RegistryCreateError {
                err: "Cannot register as king".to_string(),
            }),
            Self::Client {
                king_registry_addr: _,
                registrant_id,
                local_to_outbound_tx,
                inbound_messages,
                cert_der,
                ..
            } => {
                local_to_outbound_tx
                    .send(RegistryPacket::Register {
                        id: *registrant_id,
                        cert_der: cert_der.clone(),
                    })
                    .map_err(|err| Error::RegistrySendError {
                        err: err.to_string(),
                    })?;

                let response = inbound_messages.lock().await.recv().await.ok_or(
                    Error::RegistryCreateError {
                        err: "No response received".to_string(),
                    },
                )?;

                if !matches!(
                    &response,
                    &RegistryPacket::RegisterResponse { success: true, .. }
                ) {
                    return Err(Error::RegistryCreateError {
                        err: "Unexpected response".to_string(),
                    });
                }

                Ok(())
            }
        }
    }
}

fn to_addr<T: std::net::ToSocketAddrs>(addr: T) -> Result<SocketAddr, Error> {
    addr.to_socket_addrs()
        .map_err(|err| Error::RegistryCreateError {
            err: err.to_string(),
        })?
        .next()
        .ok_or(Error::RegistryCreateError {
            err: "No address found".to_string(),
        })
}

fn handle_single_connection(
    connection: TlsStream<TcpStream>,
    mut local_to_outbound_rx: UnboundedReceiver<RegistryPacket>,
    inbound_to_local_tx: tokio::sync::mpsc::UnboundedSender<RegistryPacket>,
) {
    let (mut sink, mut stream) = mpc_net::multi::wrap_stream(connection).split();
    // Now, take the sink and spawn a task to listen for messages that need to be sent outbound
    tokio::task::spawn(async move {
        while let Some(outbound_message) = local_to_outbound_rx.recv().await {
            if let Err(err) = send_stream(&mut sink, outbound_message).await {
                log::error!("[Registry] Failed to send message to king: {err:?}");
            }
        }
    });

    // Now, the stream will be used to receive messages from the king
    tokio::task::spawn(async move {
        loop {
            match recv_stream(&mut stream).await {
                Ok(message) => {
                    if let Err(err) = inbound_to_local_tx.send(message) {
                        log::error!("[Registry] Failed to send message to gadget: {err:?}");
                        break;
                    }
                }
                Err(Error::RegistryRecvError { err }) => {
                    log::error!("[Registry] Failed to receive message from king: {err:?}");
                    break;
                }
                Err(err) => {
                    log::error!("[Registry] Failed to receive message from king: {err:?}");
                    break;
                }
            }
        }
    });
}

#[derive(Serialize, Deserialize)]
pub enum RegistryPacket {
    Register { id: RegistantId, cert_der: Vec<u8> },
    RegisterResponse { id: RegistantId, success: bool },
    // A message for the substrate gadget
    SubstrateGadgetMessage { payload: GadgetProtocolMessage },
}

fn handle_stream_as_king(
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: SocketAddr,
    registrants: Arc<Mutex<HashMap<RegistantId, Registrant>>>,
    to_outbound_txs: Arc<RwLock<HashMap<RegistantId, UnboundedSender<RegistryPacket>>>>,
    to_gadget: UnboundedSender<RegistryPacket>,
) {
    tokio::task::spawn(async move {
        let stream = match tls_acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(err) => {
                log::error!("[Registry] Failed to upgrade connection from {peer_addr}: {err:?}");
                return;
            }
        };

        let stream = TlsStream::Server(stream);
        let wrapped_stream = mpc_net::multi::wrap_stream(stream);
        let (mut sink, mut stream) = wrapped_stream.split();
        let (to_outbound_tx, mut to_outbound_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut peer_id = None;

        // Spawn a task allowing the king to send messages to the peer from the gadget
        tokio::task::spawn(async move {
            while let Some(message) = to_outbound_rx.recv().await {
                if let Err(err) = send_stream(&mut sink, message).await {
                    log::error!("[Registry] Failed to send message to peer {peer_addr}: {err:?}");
                    break;
                }
            }

            log::warn!("to_outbound_rx closed");
        });

        while let Some(Ok(message)) = stream.next().await {
            match bincode2::deserialize::<RegistryPacket>(&message) {
                Ok(packet) => match packet {
                    RegistryPacket::Register { id, cert_der } => {
                        log::info!("[Registry] Received registration for id {id}");
                        to_outbound_txs.write().insert(id, to_outbound_tx.clone());
                        peer_id = Some(id);
                        let mut registrants = registrants.lock().await;
                        registrants.insert(id, Registrant { id, cert_der });
                        if let Err(err) = to_outbound_tx
                            .send(RegistryPacket::RegisterResponse { id, success: true })
                        {
                            log::error!("[Registry] Failed to send registration response: {err:?}");
                        }
                    }
                    RegistryPacket::SubstrateGadgetMessage { payload } => {
                        if let Err(err) =
                            to_gadget.send(RegistryPacket::SubstrateGadgetMessage { payload })
                        {
                            log::error!("[Registry] Failed to send message to gadget: {err:?}");
                        }
                    }
                    _ => {
                        log::info!("[Registry] Received invalid packet");
                    }
                },
                Err(err) => {
                    log::info!("[Registry] Received invalid packet: {err}");
                }
            }
        }

        // Deregister peer
        if let Some(id) = peer_id {
            let mut registrants = registrants.lock().await;
            registrants.remove(&id);
        }

        log::warn!("[Registry] Connection closed to peer {peer_addr}")
    });
}

async fn send_stream<R: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut SplitSink<WrappedStream<R>, Bytes>,
    payload: RegistryPacket,
) -> Result<(), Error> {
    let serialized = bincode2::serialize(&payload).map_err(|err| Error::RegistrySendError {
        err: err.to_string(),
    })?;

    stream
        .send(serialized.into())
        .await
        .map_err(|err| Error::RegistrySendError {
            err: err.to_string(),
        })
}

async fn recv_stream<R: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut SplitStream<WrappedStream<R>>,
) -> Result<RegistryPacket, Error> {
    let message = stream
        .next()
        .await
        .ok_or(Error::RegistryRecvError {
            err: "Stream closed".to_string(),
        })?
        .map_err(|err| Error::RegistryRecvError {
            err: err.to_string(),
        })?;

    let deserialized =
        bincode2::deserialize(&message).map_err(|err| Error::RegistrySerializationError {
            err: err.to_string(),
        })?;

    Ok(deserialized)
}

#[async_trait]
impl Network for ZkNetworkService {
    async fn next_message(
        &self,
    ) -> Option<<WebbWorkManager as WorkManagerInterface>::ProtocolMessage> {
        match self {
            Self::King {
                inbound_messages, ..
            }
            | Self::Client {
                inbound_messages, ..
            } => loop {
                match inbound_messages.lock().await.recv().await {
                    Some(RegistryPacket::SubstrateGadgetMessage { payload }) => {
                        return Some(payload)
                    }
                    Some(_packet) => {
                        log::error!("[Registry] Received invalid packet");
                    }
                    None => {
                        log::error!("[Registry] Inbound messages closed");
                        return None;
                    }
                }
            },
        }
    }

    #[allow(clippy::collapsible_else_if)]
    async fn send_message(
        &self,
        message: <WebbWorkManager as WorkManagerInterface>::ProtocolMessage,
    ) -> Result<(), Error> {
        if let Some(to) = message.to {
            match self {
                Self::Client {
                    local_to_outbound_tx,
                    ..
                } => {
                    if to != 0 {
                        return Err(Error::RegistrySendError {
                            err: "Cannot send message to non-king as client".to_string(),
                        });
                    }

                    local_to_outbound_tx
                        .send(RegistryPacket::SubstrateGadgetMessage { payload: message })
                        .map_err(|err| Error::RegistrySendError {
                            err: err.to_string(),
                        })
                }

                Self::King {
                    to_outbound_txs, ..
                } => to_outbound_txs
                    .read()
                    .get(&to)
                    .ok_or(Error::RegistrySendError {
                        err: "No connection to registrant".to_string(),
                    })?
                    .send(RegistryPacket::SubstrateGadgetMessage { payload: message })
                    .map_err(|err| Error::RegistrySendError {
                        err: err.to_string(),
                    }),
            }
        } else {
            if let Self::King {
                to_outbound_txs, ..
            } = self
            {
                // Send to ALL peers
                for (_, tx) in to_outbound_txs.read().iter() {
                    tx.send(RegistryPacket::SubstrateGadgetMessage {
                        payload: message.clone(),
                    })
                    .map_err(|err| Error::RegistrySendError {
                        err: err.to_string(),
                    })?;
                }

                Ok(())
            } else {
                Err(Error::RegistrySendError {
                    err: "Cannot broadcast message as client".to_string(),
                })
            }
        }
    }

    async fn run(&self) -> Result<(), Error> {
        match self {
            Self::King {
                listener,
                registrants,
                to_gadget,
                identity,
                to_outbound_txs,
                ..
            } => {
                let listener = listener.lock().await.take().expect("Should exist");
                let tls_acceptor = create_server_tls_acceptor(identity.clone()).map_err(|err| {
                    Error::RegistryCreateError {
                        err: format!("{err:?}"),
                    }
                })?;

                while let Ok((stream, peer_addr)) = listener.accept().await {
                    log::info!("[Registry] Accepted connection from {peer_addr}, upgrading to TLS");
                    handle_stream_as_king(
                        tls_acceptor.clone(),
                        stream,
                        peer_addr,
                        registrants.clone(),
                        to_outbound_txs.clone(),
                        to_gadget.clone(),
                    );
                }

                Err(Error::RegistryCreateError {
                    err: "Listener closed".to_string(),
                })
            }
            Self::Client { .. } => Ok(()),
        }
    }
}
