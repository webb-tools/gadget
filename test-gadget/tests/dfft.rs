#[cfg(test)]
mod tests {
    use gadget_core::job_manager::SendFuture;
    use std::collections::HashMap;
    use std::error::Error;
    use std::pin::Pin;
    use test_gadget::work_manager::TestAsyncProtocolParameters;
    use test_gadget::TestBundle;
    use tracing_subscriber::fmt::SubscriberBuilder;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    use ark_bls12_377::Fr;
    use ark_ff::{FftField, PrimeField};
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use async_trait::async_trait;
    use dist_primitives::{
        channel::MpcSerNet,
        dfft::{d_fft, fft_in_place_rearrange},
        utils::pack::transpose,
    };
    use mpc_net::{MpcNet, MpcNetError, MultiplexedStreamID};
    use secret_sharing::pss::PackedSharingParams;
    use serde::{Deserialize, Serialize};
    use test_gadget::message::TestProtocolMessage;
    use test_gadget::test_network::InMemoryNetwork;
    use tokio::sync::Mutex;

    pub async fn d_fft_test<F: FftField + PrimeField, Net: MpcNet>(
        pp: &PackedSharingParams<F>,
        dom: &Radix2EvaluationDomain<F>,
        net: &Net,
    ) {
        log::info!("Starting d_fft_test on party {}", net.party_id());
        let mbyl: usize = dom.size() / pp.l;
        // We apply FFT on this vector
        // let mut x = vec![F::ONE; cd.m];
        let mut x: Vec<F> = Vec::new();
        for i in 0..dom.size() {
            x.push(F::from(i as u64));
        }

        // Output to test against
        let should_be_output = dom.fft(&x);
        log::info!("ABC0 on party {}", net.party_id());
        fft_in_place_rearrange(&mut x);
        let mut pcoeff: Vec<Vec<F>> = Vec::new();
        for i in 0..mbyl {
            pcoeff.push(x.iter().skip(i).step_by(mbyl).cloned().collect::<Vec<_>>());
            pp.pack_from_public_in_place(&mut pcoeff[i]);
        }
        log::info!("ABC1 on party {}", net.party_id());

        let pcoeff_share = pcoeff
            .iter()
            .map(|x| x[net.party_id() as usize])
            .collect::<Vec<_>>();

        log::info!("ABC2 on party {}", net.party_id());
        // Rearranging x

        let peval_share = d_fft(
            pcoeff_share,
            false,
            1,
            false,
            dom,
            pp,
            net,
            MultiplexedStreamID::Zero,
        )
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        log::info!("ABC3 on party {}", net.party_id());

        // Send to king who reconstructs and checks the answer
        net.send_to_king(&peval_share, MultiplexedStreamID::Zero)
            .await
            .unwrap()
            .map(|peval_shares| {
                let peval_shares = transpose(peval_shares);

                let pevals: Vec<F> = peval_shares
                    .into_iter()
                    .flat_map(|x| pp.unpack(x))
                    .rev()
                    .collect();

                log::info!("ABC4 on party {}", net.party_id());
                if net.is_king() {
                    assert_eq!(should_be_output, pevals);
                }
                log::info!("ABC5 on party {}", net.party_id());
            });

        log::info!("ABC-FINAL on party {}", net.party_id());
    }

    pub fn setup_log() {
        let _ = SubscriberBuilder::default()
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .try_init();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dfft() -> Result<(), Box<dyn Error>> {
        setup_log();
        test_gadget::simulate_test(
            5,
            10,
            // Give 10 minutes per test
            std::time::Duration::from_secs(60 * 10),
            vec![0],
            async_proto_generator,
        )
        .await
    }

    fn async_proto_generator(
        mut params: TestAsyncProtocolParameters<TestBundle>,
    ) -> Pin<Box<dyn SendFuture<'static, ()>>> {
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

            let mut txs = vec![];
            let mut rxs = vec![];
            for _ in 0..params.test_bundle.n_peers {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                txs.push(tx);
                rxs.push(Mutex::new(rx));
            }

            let network = ZkNetworkOverGadgetNetwork {
                gadget_network: params.test_bundle.network,
                rxs,
                n_peers: params.test_bundle.n_peers,
                party_id: params.test_bundle.party_id,
                associated_block_id: params.associated_block_id,
                associated_session_id: params.associated_session_id,
                associated_ssid: params.associated_ssid,
                associated_task_id: params.associated_task_id,
            };

            tokio::task::spawn(async move {
                while let Some(message) = params.protocol_message_rx.recv().await {
                    let deserialized: MpcNetMessage =
                        bincode2::deserialize(&message.payload).expect("Failed to deser message");
                    let tx = &txs[deserialized.sid as usize];
                    tx.send(deserialized).expect("Failed to send message");
                }
            });

            let pp = PackedSharingParams::<Fr>::new(2);
            let dom = Radix2EvaluationDomain::<Fr>::new(1024).unwrap();
            d_fft_test::<Fr, _>(&pp, &dom, &network).await;
            on_end_tx.send(()).expect("Failed to send on_end signal");
        })
    }

    struct ZkNetworkOverGadgetNetwork {
        gadget_network: InMemoryNetwork,
        rxs: Vec<Mutex<tokio::sync::mpsc::UnboundedReceiver<MpcNetMessage>>>,
        n_peers: usize,
        party_id: u32,
        associated_block_id: u64,
        associated_session_id: u64,
        associated_ssid: u16,
        associated_task_id: [u8; 8],
    }

    #[derive(Serialize, Deserialize)]
    struct MpcNetMessage {
        sid: MultiplexedStreamID,
        payload: bytes::Bytes,
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

        async fn client_send_or_king_receive(
            &self,
            bytes: &[u8],
            sid: MultiplexedStreamID,
        ) -> Result<Option<Vec<bytes::Bytes>>, MpcNetError> {
            if self.is_king() {
                let count = self.n_parties() - 1;
                let mut packets = HashMap::new();

                for _ in 0..count {
                    let payload = recv_bytes(sid, self).await;
                    log::info!("King received packet from {from}", from = payload.source);
                    let from = payload.source;
                    packets.insert(from, payload.payload);
                }

                packets.insert(0, bytes.to_vec().into()); // Insert the king's value
                log::info!("Received packets from keys: {:?}", packets.keys());
                let mut packets_ordered = vec![];
                for i in 0..self.n_parties() {
                    let payload = packets.remove(&(i as u32)).expect("Missing packet");
                    packets_ordered.push(payload);
                }

                log::info!("King done with receive, ret = {}", packets_ordered.len());
                Ok(Some(packets_ordered))
            } else {
                send_bytes(sid, bytes.to_vec().into(), self, Some(0)).await;
                Ok(None)
            }
        }

        async fn client_receive_or_king_send(
            &self,
            bytes: Option<Vec<bytes::Bytes>>,
            sid: MultiplexedStreamID,
        ) -> Result<bytes::Bytes, MpcNetError> {
            if self.is_king() {
                let payloads = bytes.expect("Missing bytes");
                let my_payload = payloads[self.party_id as usize].clone();
                let m = my_payload.len();
                // Send bytes to each party except us
                for (i, payload) in payloads
                    .into_iter()
                    .enumerate()
                    .take(self.n_peers)
                    .filter(|r| r.0 != self.party_id as usize)
                {
                    assert_eq!(payload.len(), m);
                    send_bytes(sid, payload, self, Some(i as u32)).await;
                }

                log::info!("King SEND | DONE");

                // Return our own bytes
                Ok(my_payload)
            } else {
                let payload = recv_bytes(sid, self).await;
                Ok(payload.payload)
            }
        }
    }

    async fn send_bytes(
        sid: MultiplexedStreamID,
        payload: bytes::Bytes,
        network: &ZkNetworkOverGadgetNetwork,
        to: Option<u32>,
    ) {
        let mpc_net_payload = MpcNetMessage {
            sid,
            payload,
            source: network.party_id,
        };

        let serialized =
            bincode2::serialize(&mpc_net_payload).expect("Failed to serialize message");

        let gadget_protocol_message = TestProtocolMessage {
            payload: serialized,
            from: network.party_id,
            to,
            associated_block_id: network.associated_block_id,
            associated_session_id: network.associated_session_id,
            associated_ssid: network.associated_ssid,
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
        network: &ZkNetworkOverGadgetNetwork,
    ) -> MpcNetMessage {
        let rx = &network.rxs[sid as usize];
        rx.lock()
            .await
            .recv()
            .await
            .expect("Failed to receive bytes")
    }
}
