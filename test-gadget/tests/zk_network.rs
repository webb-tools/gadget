#[cfg(test)]
mod tests {
    use gadget_common::utils::*;
    use gadget_core::job_manager::SendFuture;
    use std::collections::HashMap;
    use std::error::Error;
    use std::pin::Pin;
    use test_gadget::work_manager::TestAsyncProtocolParameters;
    use test_gadget::TestBundle;
    use tracing_subscriber::fmt::SubscriberBuilder;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    use async_trait::async_trait;
    use bytes::Bytes;
    use gadget_core::job::JobError;
    use mpc_net::{MpcNet, MpcNetError, MultiplexedStreamID};
    use serde::{Deserialize, Serialize};
    use test_gadget::message::{TestProtocolMessage, UserID};
    use test_gadget::test_network::InMemoryNetwork;
    use tokio::sync::Mutex;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 10);

    pub fn setup_log() {
        let _ = SubscriberBuilder::default()
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_zk_network() -> Result<(), Box<dyn Error>> {
        setup_log();
        test_gadget::simulate_test(
            5,
            10,
            std::time::Duration::from_secs(60 * 10),
            vec![0],
            async_proto_generator,
        )
        .await
    }

    fn async_proto_generator(
        mut params: TestAsyncProtocolParameters<TestBundle>,
    ) -> Pin<Box<dyn SendFuture<'static, Result<(), JobError>>>> {
        Box::pin(async move {
            params
                .start_rx
                .take()
                .expect("Already started")
                .await
                .expect("Failed to start");
            let on_end_tx = params.test_bundle.count_finished_tx.clone();
            // We need to create a network that implements MpcNet. This means we need multiplexing.
            // To multiplex the inbound stream from the JobManager, we need to take the receive handle
            // and spawn a task that will receive messages and send them to the appropriate channel.
            // For sending messages, the payload we send to the JobManager needs to be multiplexed with
            // stream IDs.

            let mut txs = HashMap::new();
            let mut rxs = HashMap::new();
            for peer_id in 0..params.test_bundle.n_peers {
                // Create 3 multiplexed channels
                let mut txs_for_this_peer = vec![];
                let mut rxs_for_this_peer = vec![];
                for _ in 0..3 {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                    txs_for_this_peer.push(tx);
                    rxs_for_this_peer.push(Mutex::new(rx));
                }

                txs.insert(peer_id as u32, txs_for_this_peer);
                rxs.insert(peer_id as u32, rxs_for_this_peer);
            }

            let network = ZkNetworkOverGadgetNetwork {
                gadget_network: params.test_bundle.network,
                rxs,
                n_peers: params.test_bundle.n_peers,
                party_id: params.test_bundle.party_id,
                associated_block_id: params.associated_block_id,
                associated_session_id: params.associated_session_id,
                associated_retry_id: params.associated_retry_id,
                associated_task_id: params.associated_task_id,
            };

            tokio::task::spawn(async move {
                while let Some(message) = params.protocol_message_rx.recv().await {
                    let deserialized: MpcNetMessage =
                        bincode::deserialize(&message.payload).expect("Failed to deser message");
                    let txs = &txs[&deserialized.source];
                    let tx = &txs[deserialized.sid as usize];
                    tx.send(deserialized).expect("Failed to send");
                }
            });

            let expected_sum = (0..params.test_bundle.n_peers)
                .map(|i| i as UserID)
                .sum::<UserID>();

            for sid in [
                MultiplexedStreamID::Zero,
                MultiplexedStreamID::One,
                MultiplexedStreamID::Two,
            ] {
                let message = bincode::serialize(&params.test_bundle.party_id)
                    .expect("Failed to serialize message");
                let king_response = if let Some(messages) = network
                    .client_send_or_king_receive(&message, sid, TIMEOUT)
                    .await
                    .expect("Failed to send")
                {
                    let messages = match messages {
                        mpc_net::ClientSendOrKingReceiveResult::Full(m) => m,
                        mpc_net::ClientSendOrKingReceiveResult::Partial(_) => todo!(),
                    };
                    assert_eq!(messages.len(), params.test_bundle.n_peers);
                    let mut sum = 0;
                    for message in messages.into_iter() {
                        let peer_id: UserID =
                            deserialize(&message).expect("Failed to deserialize message");
                        sum += peer_id
                    }
                    assert_eq!(
                        sum, expected_sum,
                        "Sum of peer IDs should be equal to sum of all peer IDs"
                    );

                    let sum = Bytes::from(serialize(&sum).expect("Failed to serialize message"));
                    Some(
                        (0..params.test_bundle.n_peers)
                            .map(|_| sum.clone())
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                };

                let sum = network
                    .client_receive_or_king_send(king_response, sid)
                    .await
                    .expect("Failed to receive");
                let sum: UserID = deserialize(&sum).expect("Failed to deserialize message");
                assert_eq!(
                    sum, expected_sum,
                    "Sum of peer IDs should be equal to sum of all peer IDs"
                );
            }

            on_end_tx.send(()).expect("Failed to send on_end signal");
            Ok(())
        })
    }

    struct ZkNetworkOverGadgetNetwork {
        gadget_network: InMemoryNetwork,
        rxs: HashMap<u32, Vec<Mutex<tokio::sync::mpsc::UnboundedReceiver<MpcNetMessage>>>>,
        n_peers: usize,
        party_id: u32,
        associated_block_id: u64,
        associated_session_id: u64,
        associated_retry_id: u16,
        associated_task_id: [u8; 8],
    }

    #[derive(Serialize, Deserialize)]
    struct MpcNetMessage {
        sid: MultiplexedStreamID,
        payload: Bytes,
        source: u32,
    }

    #[async_trait]
    impl MpcNet for ZkNetworkOverGadgetNetwork {
        fn n_parties(&self) -> usize {
            self.n_peers
        }

        fn party_id(&self) -> u32 {
            self.party_id
        }

        fn is_init(&self) -> bool {
            true
        }

        async fn recv_from(&self, id: u32, sid: MultiplexedStreamID) -> Result<Bytes, MpcNetError> {
            Ok(recv_bytes(sid, id, self).await.payload)
        }

        async fn send_to(
            &self,
            id: u32,
            bytes: Bytes,
            sid: MultiplexedStreamID,
        ) -> Result<(), MpcNetError> {
            send_bytes(sid, bytes, self, Some(id)).await;
            Ok(())
        }
    }

    async fn send_bytes(
        sid: MultiplexedStreamID,
        payload: Bytes,
        network: &ZkNetworkOverGadgetNetwork,
        to: Option<u32>,
    ) {
        let mpc_net_payload = MpcNetMessage {
            sid,
            payload,
            source: network.party_id,
        };

        let serialized = serialize(&mpc_net_payload).expect("Failed to serialize message");

        let gadget_protocol_message = TestProtocolMessage {
            payload: serialized,
            from: network.party_id,
            to,
            associated_block_id: network.associated_block_id,
            associated_session_id: network.associated_session_id,
            associated_retry_id: network.associated_retry_id,
            associated_task_id: network.associated_task_id,
        };

        if let Some(to) = to {
            assert_ne!(to, network.party_id, "Cannot send to self");
            network
                .gadget_network
                .send_to(gadget_protocol_message, to)
                .expect("Failed to send");
        } else {
            network
                .gadget_network
                .broadcast(network.party_id, gadget_protocol_message)
                .expect("Failed to broadcast");
        }
    }

    async fn recv_bytes(
        sid: MultiplexedStreamID,
        from: u32,
        network: &ZkNetworkOverGadgetNetwork,
    ) -> MpcNetMessage {
        let rx = &network.rxs.get(&from).expect("Should exist")[sid as usize];
        rx.lock()
            .await
            .recv()
            .await
            .expect("Failed to receive bytes")
    }
}
