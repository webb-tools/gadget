use crate::error::Error;
use async_trait::async_trait;
use core::fmt::Display;
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use sp_core::{ecdsa, sha2_256};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::Mutex;

use self::channels::UserID;

pub mod channels;
pub mod gossip;
pub mod handlers;
#[cfg(target_family = "wasm")]
pub mod matchbox;
pub mod messaging;
pub mod round_based_compat;
pub mod setup;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub struct IdentifierInfo {
    pub message_id: u64,
    pub round_id: u16,
}

impl Display for IdentifierInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_id = format!("message_id: {}", self.message_id);
        let round_id = format!("round_id: {}", self.round_id);
        write!(f, "{} {}", message_id, round_id)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct ParticipantInfo {
    pub user_id: u16,
    pub ecdsa_key: Option<sp_core::ecdsa::Public>,
}

impl Display for ParticipantInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ecdsa_key = self
            .ecdsa_key
            .map(|key| format!("ecdsa_key: {}", key))
            .unwrap_or_default();
        write!(f, "user_id: {}, {}", self.user_id, ecdsa_key)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolMessage {
    pub identifier_info: IdentifierInfo,
    pub sender: ParticipantInfo,
    pub recipient: Option<ParticipantInfo>,
    pub payload: Vec<u8>,
}

impl Display for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "identifier_info: {}, sender: {}, recipient: {:?}, payload: {:?}",
            self.identifier_info, self.sender, self.recipient, self.payload
        )
    }
}

#[async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait Network: Send + Sync + 'static {
    async fn next_message(&self) -> Option<ProtocolMessage>;
    async fn send_message(&self, message: ProtocolMessage) -> Result<(), Error>;

    fn build_protocol_message<Payload: Serialize>(
        identifier_info: IdentifierInfo,
        from: UserID,
        to: Option<UserID>,
        payload: &Payload,
        from_account_id: Option<ecdsa::Public>,
        to_network_id: Option<ecdsa::Public>,
    ) -> ProtocolMessage {
        let sender_participant_info = ParticipantInfo {
            user_id: from,
            ecdsa_key: from_account_id,
        };
        let receiver_participant_info = to.map(|to| ParticipantInfo {
            user_id: to,
            ecdsa_key: to_network_id,
        });
        ProtocolMessage {
            identifier_info,
            sender: sender_participant_info,
            recipient: receiver_participant_info,
            payload: serialize(payload).expect("Failed to serialize message"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SequencedMessage {
    seq: u64,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct PendingMessage {
    seq: u64,
    message: ProtocolMessage,
}

impl PartialEq for PendingMessage {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl Eq for PendingMessage {}

impl PartialOrd for PendingMessage {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingMessage {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq.cmp(&other.seq)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiplexedMessage {
    stream_id: StreamKey,
    payload: SequencedMessage,
}

pub struct NetworkMultiplexer {
    to_receiving_streams: ActiveStreams,
    unclaimed_receiving_streams: Arc<DashMap<StreamKey, MultiplexedReceiver>>,
    tx_to_networking_layer: MultiplexedSender,
    sequence_numbers: Arc<DashMap<CompoundStreamKey, u64>>,
}

type ActiveStreams = Arc<DashMap<StreamKey, tokio::sync::mpsc::UnboundedSender<ProtocolMessage>>>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Default, Serialize, Deserialize)]
pub struct StreamKey {
    pub task_hash: [u8; 32],
    pub round_id: i32,
}

impl From<IdentifierInfo> for StreamKey {
    fn from(identifier_info: IdentifierInfo) -> Self {
        let str_repr = identifier_info.to_string();
        let task_hash = sha2_256(str_repr.as_bytes());
        Self {
            task_hash,
            round_id: -1,
        }
    }
}

pub struct MultiplexedReceiver {
    inner: tokio::sync::mpsc::UnboundedReceiver<ProtocolMessage>,
    stream_id: StreamKey,
    // For post-drop removal purposes
    active_streams: ActiveStreams,
}

#[derive(Clone)]
pub struct MultiplexedSender {
    inner: tokio::sync::mpsc::UnboundedSender<(StreamKey, ProtocolMessage)>,
    pub(crate) stream_id: StreamKey,
}

impl MultiplexedSender {
    pub fn send(&self, message: ProtocolMessage) -> Result<(), Error> {
        self.inner
            .send((self.stream_id, message))
            .map_err(|err| Error::Other(err.to_string()))
    }
}

impl Stream for MultiplexedReceiver {
    type Item = ProtocolMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inner).poll_recv(cx)
    }
}

impl Deref for MultiplexedReceiver {
    type Target = tokio::sync::mpsc::UnboundedReceiver<ProtocolMessage>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for MultiplexedReceiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for MultiplexedReceiver {
    fn drop(&mut self) {
        let _ = self.active_streams.remove(&self.stream_id);
    }
}

// Since a single stream can be used for multiple users, and, multiple users assign seq's independently,
// we need to make a key that is unique for each (send->dest) pair and stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct CompoundStreamKey {
    stream_id: StreamKey,
    send_user_id: UserID,
    recv_user_id: Option<UserID>,
}

impl NetworkMultiplexer {
    pub fn new<N: Network>(network: N) -> Self {
        let (tx_to_networking_layer, mut rx_from_substreams) =
            tokio::sync::mpsc::unbounded_channel();
        let this = NetworkMultiplexer {
            to_receiving_streams: Arc::new(DashMap::new()),
            unclaimed_receiving_streams: Arc::new(DashMap::new()),
            tx_to_networking_layer: MultiplexedSender {
                inner: tx_to_networking_layer,
                stream_id: Default::default(),
            },
            sequence_numbers: Arc::new(DashMap::new()),
        };

        let active_streams = this.to_receiving_streams.clone();
        let unclaimed_streams = this.unclaimed_receiving_streams.clone();
        let tx_to_networking_layer = this.tx_to_networking_layer.clone();
        let sequence_numbers = this.sequence_numbers.clone();

        drop(tokio::spawn(async move {
            let network_clone = &network;

            let task1 = async move {
                while let Some((stream_id, msg)) = rx_from_substreams.recv().await {
                    let compound_key = CompoundStreamKey {
                        stream_id,
                        send_user_id: msg.sender.user_id,
                        recv_user_id: msg.recipient.as_ref().map(|p| p.user_id),
                    };

                    let mut seq = sequence_numbers.entry(compound_key).or_insert(0);
                    let current_seq = *seq;
                    *seq += 1;

                    crate::trace!(
                        "SEND SEQ {current_seq} FROM {} | StreamKey: {:?}",
                        msg.sender.user_id,
                        hex::encode(bincode::serialize(&compound_key).unwrap())
                    );

                    let multiplexed_message = MultiplexedMessage {
                        stream_id,
                        payload: SequencedMessage {
                            seq: current_seq,
                            payload: msg.payload,
                        },
                    };

                    let message = ProtocolMessage {
                        identifier_info: msg.identifier_info,
                        sender: msg.sender,
                        recipient: msg.recipient,
                        payload: bincode::serialize(&multiplexed_message)
                            .expect("Failed to serialize message"),
                    };

                    if let Err(err) = network_clone.send_message(message).await {
                        crate::error!(%err, "Failed to send message to network");
                        break;
                    }
                }
            };

            let task2 = async move {
                let mut pending_messages: HashMap<
                    CompoundStreamKey,
                    BinaryHeap<Reverse<PendingMessage>>,
                > = Default::default();
                let mut expected_seqs: HashMap<CompoundStreamKey, u64> = Default::default();

                while let Some(mut msg) = network_clone.next_message().await {
                    if let Ok(multiplexed_message) =
                        bincode::deserialize::<MultiplexedMessage>(&msg.payload)
                    {
                        let stream_id = multiplexed_message.stream_id;
                        let compound_key = CompoundStreamKey {
                            stream_id,
                            send_user_id: msg.sender.user_id,
                            recv_user_id: msg.recipient.as_ref().map(|p| p.user_id),
                        };
                        let seq = multiplexed_message.payload.seq;
                        msg.payload = multiplexed_message.payload.payload;

                        // Get or create the pending heap for this stream
                        let pending = pending_messages.entry(compound_key).or_default();
                        let expected_seq = expected_seqs.entry(compound_key).or_default();

                        let send_user = msg.sender.user_id;
                        let recv_user = msg
                            .recipient
                            .as_ref()
                            .map(|p| p.user_id as i32)
                            .unwrap_or(-1);

                        let compound_key_hex =
                            hex::encode(bincode::serialize(&compound_key).unwrap());
                        crate::trace!(
                            "RECV SEQ {seq} FROM {} as user {:?} | Expecting: {} | StreamKey: {:?}",
                            send_user,
                            recv_user,
                            *expected_seq,
                            compound_key_hex,
                        );

                        // Add the message to pending
                        pending.push(Reverse(PendingMessage { seq, message: msg }));

                        // Try to deliver messages in order
                        if let Some(active_receiver) = active_streams.get(&stream_id) {
                            while let Some(Reverse(PendingMessage { seq, message: _ })) =
                                pending.peek()
                            {
                                if *seq != *expected_seq {
                                    break;
                                }

                                crate::trace!("DELIVERING SEQ {seq} FROM {} as user {:?} | Expecting: {} | StreamKey: {:?}", send_user, recv_user, *expected_seq, compound_key_hex);

                                *expected_seq += 1;

                                let message = pending.pop().unwrap().0.message;

                                if let Err(err) = active_receiver.send(message) {
                                    crate::error!(%err, "Failed to send message to receiver");
                                    let _ = active_streams.remove(&stream_id);
                                    break;
                                }
                            }
                        } else {
                            let (tx, rx) = Self::create_multiplexed_stream_inner(
                                tx_to_networking_layer.clone(),
                                &active_streams,
                                stream_id,
                            );

                            // Deliver any pending messages in order
                            while let Some(Reverse(PendingMessage { seq, message: _ })) =
                                pending.peek()
                            {
                                if *seq != *expected_seq {
                                    break;
                                }

                                crate::warn!("EARLY DELIVERY SEQ {seq} FROM {} as user {:?} | Expecting: {} | StreamKey: {:?}", send_user, recv_user, *expected_seq, compound_key_hex);

                                *expected_seq += 1;

                                let message = pending.pop().unwrap().0.message;

                                if let Err(err) = tx.send(message) {
                                    crate::error!(%err, "Failed to send message to receiver");
                                    break;
                                }
                            }

                            let _ = unclaimed_streams.insert(stream_id, rx);
                        }
                    } else {
                        crate::error!("Failed to deserialize message");
                    }
                }
            };

            tokio::select! {
                _ = task1 => {
                    crate::error!("Task 1 exited");
                },
                _ = task2 => {
                    crate::error!("Task 2 exited");
                }
            }
        }));

        this
    }

    pub fn multiplex(&self, id: impl Into<StreamKey>) -> SubNetwork {
        let id = id.into();
        let mut tx_to_networking_layer = self.tx_to_networking_layer.clone();
        if let Some(unclaimed) = self.unclaimed_receiving_streams.remove(&id) {
            tx_to_networking_layer.stream_id = id;
            return SubNetwork {
                tx: tx_to_networking_layer,
                rx: Some(unclaimed.1.into()),
            };
        }

        let (tx, rx) = Self::create_multiplexed_stream_inner(
            tx_to_networking_layer,
            &self.to_receiving_streams,
            id,
        );

        SubNetwork {
            tx,
            rx: Some(rx.into()),
        }
    }

    /// Creates a subnetwork, and also forwards all messages to the given channel. The network cannot be used to
    /// receive messages since the messages will be forwarded to the provided channel.
    pub fn multiplex_with_forwarding(
        &self,
        id: impl Into<StreamKey>,
        forward_tx: tokio::sync::mpsc::UnboundedSender<ProtocolMessage>,
    ) -> SubNetwork {
        let mut network = self.multiplex(id);
        let rx = network.rx.take().expect("Rx from network should be Some");
        let forwarding_task = async move {
            let mut rx = rx.into_inner();
            while let Some(msg) = rx.recv().await {
                crate::info!(
                    "Round {}: Received message from {} to {:?} (id: {})",
                    msg.identifier_info.round_id,
                    msg.sender.user_id,
                    msg.recipient.as_ref().map(|p| p.user_id),
                    msg.identifier_info.message_id,
                );
                if let Err(err) = forward_tx.send(msg) {
                    crate::error!(%err, "Failed to forward message to network");
                    // TODO: Add AtomicBool to make sending stop
                    break;
                }
            }
        };

        drop(tokio::spawn(forwarding_task));

        network
    }

    fn create_multiplexed_stream_inner(
        mut tx_to_networking_layer: MultiplexedSender,
        active_streams: &ActiveStreams,
        stream_id: StreamKey,
    ) -> (MultiplexedSender, MultiplexedReceiver) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        if active_streams.insert(stream_id, tx).is_some() {
            crate::warn!(
                "Stream ID {stream_id:?} already exists! Existing stream will be replaced"
            );
        }
        tx_to_networking_layer.stream_id = stream_id;

        (
            tx_to_networking_layer,
            MultiplexedReceiver {
                inner: rx,
                stream_id,
                active_streams: active_streams.clone(),
            },
        )
    }
}

impl<N: Network> From<N> for NetworkMultiplexer {
    fn from(network: N) -> Self {
        Self::new(network)
    }
}

pub struct SubNetwork {
    tx: MultiplexedSender,
    rx: Option<Mutex<MultiplexedReceiver>>,
}

impl SubNetwork {
    pub fn send(&self, message: ProtocolMessage) -> Result<(), Error> {
        self.tx.send(message)
    }

    pub async fn recv(&self) -> Option<ProtocolMessage> {
        self.rx.as_ref()?.lock().await.next().await
    }
}

#[async_trait]
impl Network for SubNetwork {
    async fn next_message(&self) -> Option<ProtocolMessage> {
        self.recv().await
    }

    async fn send_message(&self, message: ProtocolMessage) -> Result<(), Error> {
        self.send(message)
    }
}

pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, serde_json::Error>
where
    T: Deserialize<'a>,
{
    serde_json::from_slice::<T>(data)
}

pub fn serialize(object: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::setup_log;
    use futures::{stream, StreamExt};
    use gossip::GossipHandle;
    use serde::{Deserialize, Serialize};
    use sp_core::Pair;
    use std::collections::BTreeMap;
    use std::future::Future;

    const TOPIC: &str = "/gadget/test/1.0.0";

    #[derive(Debug, Serialize, Deserialize, Clone)]
    enum Msg {
        Round1(Round1Msg),
        Round2(Round2Msg),
        Round3(Round3Msg),
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Round1Msg {
        pub power: u16,
        pub hitpoints: u16,
        pub armor: u16,
        pub name: String,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Round2Msg {
        pub x: u16,
        pub y: u16,
        pub z: u16,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct Round3Msg {
        rotation: u16,
        velocity: (u16, u16, u16),
    }

    const NODE_COUNT: u16 = 10;

    async fn wait_for_nodes_connected(nodes: &[GossipHandle]) {
        let node_count = nodes.len();

        // wait for the nodes to connect to each other
        let max_retries = 30 * node_count;
        let mut retry = 0;
        loop {
            crate::debug!(%node_count, %max_retries, %retry, "Checking if all nodes are connected to each other");
            let connected = nodes
                .iter()
                .map(|node| node.connected_peers())
                .collect::<Vec<_>>();

            let all_connected = connected
                .iter()
                .enumerate()
                .inspect(|(node, peers)| crate::debug!("Node {node} has {peers} connected peers"))
                .all(|(_, &peers)| peers == node_count - 1);
            if all_connected {
                crate::debug!("All nodes are connected to each other");
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            retry += 1;
            if retry > max_retries {
                panic!("Failed to connect all nodes to each other");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_p2p() {
        setup_log();
        let nodes = stream::iter(0..NODE_COUNT)
            .map(|_| node())
            .collect::<Vec<_>>()
            .await;

        wait_for_nodes_connected(&nodes).await;

        let mut tasks = Vec::new();
        for (i, node) in nodes.into_iter().enumerate() {
            let task = tokio::spawn(run_protocol(node, i as u16));
            tasks.push(task);
        }
        // Wait for all tasks to finish
        let results = futures::future::try_join_all(tasks)
            .await
            .expect("Failed to run protocol");
        // Assert that all are okay.
        assert!(
            results.iter().all(|r| r.is_ok()),
            "Some nodes failed to run protocol"
        );
    }

    async fn run_protocol<N: Network>(node: N, i: u16) -> Result<(), crate::Error> {
        let task_hash = [0u8; 32];
        // Safety note: We should be passed a NetworkMultiplexer, and all uses of the N: Network
        // used throughout the program must also use the multiplexer to prevent mixed messages.
        let multiplexer = NetworkMultiplexer::new(node);

        let round1_network = multiplexer.multiplex(StreamKey {
            task_hash, // To differentiate between different instances of a running program (i.e., a task)
            round_id: 0, // To differentiate between different subsets of a running task
        });

        let round2_network = multiplexer.multiplex(StreamKey {
            task_hash, // To differentiate between different instances of a running program (i.e., a task)
            round_id: 1, // To differentiate between different subsets of a running task
        });

        let round3_network = multiplexer.multiplex(StreamKey {
            task_hash, // To differentiate between different instances of a running program (i.e., a task)
            round_id: 2, // To differentiate between different subsets of a running task
        });

        //let (round1_tx, round1_rx) = node.
        // Round 1 (broadcast)
        let msg = {
            let round = Round1Msg {
                power: i * 100,
                hitpoints: (i + 1) * 50,
                armor: i + 2,
                name: format!("Player {}", i),
            };

            GossipHandle::build_protocol_message(
                IdentifierInfo {
                    message_id: 0,
                    round_id: 0,
                },
                i,
                None,
                &Msg::Round1(round),
                None,
                None,
            )
        };

        crate::debug!("Broadcast Message");
        round1_network
            .send(msg)
            .map_err(|_| crate::Error::Other("Failed to send message".into()))?;

        // Wait for all other nodes to send their messages
        let mut msgs = BTreeMap::new();
        while let Some(msg) = round1_network.recv().await {
            let m = deserialize::<Msg>(&msg.payload).unwrap();
            crate::debug!(from = %msg.sender.user_id, ?m, "Received message");
            // Expecting Round1 message
            assert!(
                matches!(m, Msg::Round1(_)),
                "Expected Round1 message but got {:?} from node {}",
                m,
                msg.sender.user_id,
            );
            let old = msgs.insert(msg.sender.user_id, m);
            assert!(
                old.is_none(),
                "Duplicate message from node {}",
                msg.sender.user_id,
            );
            // Break if all messages are received
            if msgs.len() == usize::from(NODE_COUNT) - 1 {
                break;
            }
        }
        crate::debug!("Done r1 w/ {i}");

        // Round 2 (P2P)
        let msg = Round2Msg {
            x: i * 10,
            y: (i + 1) * 20,
            z: i + 2,
        };
        let msgs = (0..NODE_COUNT)
            .filter(|&j| j != i)
            .map(|j| {
                GossipHandle::build_protocol_message(
                    IdentifierInfo {
                        message_id: 0,
                        round_id: 0,
                    },
                    i,
                    Some(j),
                    &Msg::Round2(msg.clone()),
                    None,
                    None,
                )
            })
            .collect::<Vec<_>>();
        for msg in msgs {
            let to = msg.recipient.map(|r| r.user_id).expect(
                "Recipient should be present for P2P message. This is a bug in the test code",
            );
            crate::debug!(%to, "Send P2P Message");
            round2_network.send(msg)?;
        }

        // Wait for all other nodes to send their messages
        let mut msgs = BTreeMap::new();
        while let Some(msg) = round2_network.recv().await {
            let m = deserialize::<Msg>(&msg.payload).unwrap();
            crate::debug!(from = %msg.sender.user_id, ?m, "Received message");
            // Expecting Round2 message
            assert!(
                matches!(m, Msg::Round2(_)),
                "Expected Round2 message but got {:?} from node {}",
                m,
                msg.sender.user_id,
            );
            let old = msgs.insert(msg.sender.user_id, m);
            assert!(
                old.is_none(),
                "Duplicate message from node {}",
                msg.sender.user_id,
            );
            // Break if all messages are received
            if msgs.len() == usize::from(NODE_COUNT) - 1 {
                break;
            }
        }
        crate::debug!("Done r2 w/ {i}");

        // Round 3 (broadcast)

        let msg = {
            let round = Round3Msg {
                rotation: i * 30,
                velocity: (i + 1, i + 2, i + 3),
            };
            GossipHandle::build_protocol_message(
                IdentifierInfo {
                    message_id: 0,
                    round_id: 0,
                },
                i,
                None,
                &Msg::Round3(round),
                None,
                None,
            )
        };

        crate::debug!("Broadcast Message");
        round3_network.send(msg)?;

        // Wait for all other nodes to send their messages
        let mut msgs = BTreeMap::new();
        while let Some(msg) = round3_network.recv().await {
            let m = deserialize::<Msg>(&msg.payload).unwrap();
            crate::debug!(from = %msg.sender.user_id, ?m, "Received message");
            // Expecting Round3 message
            assert!(
                matches!(m, Msg::Round3(_)),
                "Expected Round3 message but got {:?} from node {}",
                m,
                msg.sender.user_id,
            );
            let old = msgs.insert(msg.sender.user_id, m);
            assert!(
                old.is_none(),
                "Duplicate message from node {}",
                msg.sender.user_id,
            );
            // Break if all messages are received
            if msgs.len() == usize::from(NODE_COUNT) - 1 {
                break;
            }
        }
        crate::debug!("Done r3 w/ {i}");

        crate::info!(node = i, "Protocol completed");

        Ok(())
    }

    fn node_with_id() -> (gossip::GossipHandle, ecdsa::Pair) {
        let identity = libp2p::identity::Keypair::generate_ed25519();
        let ecdsa_key = sp_core::ecdsa::Pair::generate().0;
        let bind_port = 0;
        let handle = setup::start_p2p_network(setup::NetworkConfig::new_service_network(
            identity,
            ecdsa_key.clone(),
            Default::default(),
            bind_port,
            TOPIC,
        ))
        .unwrap();

        (handle, ecdsa_key)
    }

    fn node() -> gossip::GossipHandle {
        node_with_id().0
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_stress_test_multiplexer() {
        setup_log();
        crate::info!("Starting test_stress_test_multiplexer");

        let (network0, id0) = node_with_id();
        let (network1, id1) = node_with_id();
        let mut networks = vec![network0, network1];

        wait_for_nodes_connected(&networks).await;

        let (network0, network1) = (networks.remove(0), networks.remove(0));

        let public0 = id0.public();
        let public1 = id1.public();

        let multiplexer0 = NetworkMultiplexer::new(network0);
        let multiplexer1 = NetworkMultiplexer::new(network1);

        let stream_key = StreamKey {
            task_hash: sha2_256(&[255u8]),
            round_id: 100,
        };

        let sub0 = multiplexer0.multiplex(stream_key);
        let sub1 = multiplexer1.multiplex(stream_key);

        const MESSAGE_COUNT: u64 = 100;

        #[derive(Serialize, Deserialize)]
        struct StressTestPayload {
            value: u64,
        }

        let handle0 = tokio::spawn(async move {
            let sub0 = &sub0;

            let recv_task = async move {
                let mut count = 0;
                while let Some(msg) = sub0.next_message().await {
                    assert_eq!(msg.sender.user_id, 1, "Bad sender");
                    assert_eq!(msg.recipient.unwrap().user_id, 0, "Bad recipient");

                    let number: StressTestPayload = deserialize(&msg.payload).unwrap();
                    assert_eq!(number.value, count, "Bad message order");
                    count += 1;

                    if count == MESSAGE_COUNT {
                        break;
                    }
                }
            };

            let send_task = async move {
                for i in 0..MESSAGE_COUNT {
                    let msg = GossipHandle::build_protocol_message(
                        IdentifierInfo::default(),
                        0,
                        Some(1),
                        &StressTestPayload { value: i },
                        Some(public0),
                        Some(public1),
                    );
                    sub0.send(msg).unwrap();
                }
            };

            tokio::join!(recv_task, send_task)
        });

        let handle1 = tokio::spawn(async move {
            let sub1 = &sub1;

            let recv_task = async move {
                let mut count = 0;
                while let Some(msg) = sub1.next_message().await {
                    assert_eq!(msg.sender.user_id, 0, "Bad sender");
                    assert_eq!(msg.recipient.unwrap().user_id, 1, "Bad recipient");
                    let number: StressTestPayload = deserialize(&msg.payload).unwrap();
                    assert_eq!(number.value, count, "Bad message order");
                    count += 1;

                    if count == MESSAGE_COUNT {
                        break;
                    }
                }
            };

            let send_task = async move {
                for i in 0..MESSAGE_COUNT {
                    let msg = GossipHandle::build_protocol_message(
                        IdentifierInfo::default(),
                        1,
                        Some(0),
                        &StressTestPayload { value: i },
                        Some(public1),
                        Some(public0),
                    );
                    sub1.send(msg).unwrap();
                }
            };

            tokio::join!(recv_task, send_task)
        });

        // Wait for all tasks to complete
        tokio::try_join!(handle0, handle1).unwrap();
    }

    async fn get_networks() -> (GossipHandle, GossipHandle) {
        let network0 = node();
        let network1 = node();

        let mut networks = vec![network0, network1];

        wait_for_nodes_connected(&networks).await;
        (networks.remove(0), networks.remove(0))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_nested_multiplexer_no_delay() {
        setup_log();
        crate::info!("Starting test_nested_multiplexer");
        let (network0, network1) = get_networks().await;
        nested_multiplex(0, 10, network0, network1, false).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    /// This test more accurately emulates real use cases since
    /// nodes will join at different and nondeterministic times.
    /// This test should thus cover the enqueuing capacity of the multiplexer.
    async fn test_nested_multiplexer_staggered_start() {
        setup_log();
        crate::info!("Starting test_nested_multiplexer");
        let (network0, network1) = get_networks().await;
        nested_multiplex(0, 10, network0, network1, true).await;
    }

    async fn nested_multiplex<N: Network>(
        cur_depth: usize,
        max_depth: usize,
        network0: N,
        network1: N,
        rand_init_delay: bool,
    ) {
        crate::info!("At nested depth = {cur_depth}/{max_depth}");

        if cur_depth == max_depth {
            return;
        }

        let stream_key = StreamKey {
            task_hash: sha2_256(&[(cur_depth % 255) as u8]),
            round_id: 0,
        };

        let initial_delay_0 = if cur_depth % 2 == 0 && rand_init_delay {
            rand::random::<u64>() % 100
        } else {
            0
        };

        let initial_delay_1 = if cur_depth % 2 != 0 && rand_init_delay {
            rand::random::<u64>()
        } else {
            0
        };

        let task_gen =
            |network, i, i_peer, rand_delay| -> Pin<Box<dyn Future<Output = SubNetwork>>> {
                Box::pin(async move {
                    crate::info!("Peer {i} at layer {cur_depth}/{max_depth}");
                    if rand_delay != 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(rand_delay)).await;
                    }

                    let multiplexer = NetworkMultiplexer::new(network);
                    let subnetwork = multiplexer.multiplex(stream_key);

                    // Send a message in the subnetwork0 to subnetwork1 and vice versa, assert values of message
                    let payload = vec![1, 2, 3];
                    let msg = GossipHandle::build_protocol_message(
                        IdentifierInfo::default(),
                        i,
                        Some(i_peer),
                        &payload,
                        None,
                        None,
                    );

                    subnetwork.send(msg.clone()).unwrap();
                    let received_msg = subnetwork.recv().await.unwrap();
                    assert_eq!(received_msg.payload, msg.payload);
                    subnetwork
                })
            };

        let task_0 = task_gen(network0, 0, 1, initial_delay_0);
        let task_1 = task_gen(network1, 1, 0, initial_delay_1);

        let (subnetwork0, subnetwork1) = tokio::join!(task_0, task_1);

        crate::info!("Done nested depth = {cur_depth}/{max_depth}");

        Box::pin(nested_multiplex(
            cur_depth + 1,
            max_depth,
            subnetwork0,
            subnetwork1,
            rand_init_delay,
        ))
        .await
    }
}
