use crate::config::ShellConfig;
use futures::StreamExt;
use gadget_common::config::DebugLogger;
use gadget_common::prelude::KeystoreBackend;
use gadget_io::tokio::select;
use gadget_io::tokio::sync::{Mutex, RwLock};
use gadget_io::tokio::task::{spawn, JoinHandle};
use sp_core::ecdsa;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use std::time::Duration;
#[cfg(not(feature = "wasm"))]
use crate::{
    network::gossip::{GossipHandle, IntraNodePayload, MyBehaviour, NetworkServiceWithoutSwarm, MAX_MESSAGE_SIZE},
    shell::{AGENT_VERSION, CLIENT_VERSION}
};
#[cfg(not(feature = "wasm"))]
use libp2p::{
    gossipsub, gossipsub::IdentTopic, kad::store::MemoryStore, mdns, request_response,
    swarm::dial_opts::DialOpts, StreamProtocol,
};

#[allow(clippy::collapsible_else_if)]
#[cfg(not(feature = "wasm"))]
pub async fn setup_libp2p_network<KBE: KeystoreBackend>(
    identity: libp2p::identity::Keypair,
    config: &ShellConfig<KBE>,
    logger: DebugLogger,
    networks: Vec<String>,
    role_key: ecdsa::Pair,
) -> Result<(HashMap<String, GossipHandle>, JoinHandle<()>), Box<dyn Error>> {
    // Setup both QUIC (UDP) and TCP transports the increase the chances of NAT traversal
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default()
                .port_reuse(true)
                .nodelay(true), // Allow port reuse for TCP-hole punching
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic_config(|mut config| {
            config.handshake_timeout = Duration::from_secs(30);
            config
        })
        .with_dns()?
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .protocol_id_prefix("/tangle/gadget-shell-sdk/meshsub")
                .max_transmit_size(MAX_MESSAGE_SIZE)
                .validate_messages()
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // Setup gossipsub network behaviour for broadcasting
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            // Setup mDNS for peer discovery
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            // Setup request-response for direct messaging
            let p2p_config = request_response::Config::default();
            // StreamProtocols MUST begin with a forward slash
            let protocols = networks
                .iter()
                .map(|n| {
                    (
                        StreamProtocol::try_from_owned(n.clone()).expect("Invalid network name"),
                        request_response::ProtocolSupport::Full,
                    )
                })
                .collect::<Vec<_>>();

            let p2p = request_response::Behaviour::new(protocols, p2p_config);

            // Setup the identify protocol for peers to exchange information about each other, a requirement for kadmelia DHT
            let identify = libp2p::identify::Behaviour::new(
                libp2p::identify::Config::new(CLIENT_VERSION.into(), key.public())
                    .with_agent_version(AGENT_VERSION.into()),
            );

            // Setup kadmelia for DHT for peer discovery over a larger network
            let memory_db = MemoryStore::new(key.public().to_peer_id());
            let kadmelia = libp2p::kad::Behaviour::new(key.public().to_peer_id(), memory_db);

            // Setup dcutr for upgrading existing connections to use relay against the bootnodes when necessary
            // This also provided hole-punching capabilities to attempt to seek a direct connection, and fallback to relaying
            // otherwise.
            // dcutr = direct connection upgrade through relay
            let dcutr = libp2p::dcutr::Behaviour::new(key.public().to_peer_id());

            // Setup relay for using the dcutr-upgraded connections to relay messages for other peers when required
            let relay_config = libp2p::relay::Config::default();
            let relay = libp2p::relay::Behaviour::new(key.public().to_peer_id(), relay_config);

            // Setup ping for liveness checks between connections
            let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::default());

            Ok(MyBehaviour {
                gossipsub,
                mdns,
                p2p,
                identify,
                kadmelia,
                dcutr,
                relay,
                relay_client,
                ping,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to all networks
    let mut inbound_mapping = Vec::new();
    let (tx_to_outbound, mut rx_to_outbound) =
        gadget_io::tokio::sync::mpsc::unbounded_channel::<IntraNodePayload>();
    let ecdsa_peer_id_to_libp2p_id = Arc::new(RwLock::new(HashMap::new()));
    let mut handles_ret = HashMap::with_capacity(networks.len());
    for network in networks {
        let topic = IdentTopic::new(network.clone());
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        let (inbound_tx, inbound_rx) = gadget_io::tokio::sync::mpsc::unbounded_channel();
        let connected_peers = Arc::new(AtomicU32::new(0));
        inbound_mapping.push((topic.clone(), inbound_tx, connected_peers.clone()));

        handles_ret.insert(
            network,
            GossipHandle {
                connected_peers,
                topic,
                tx_to_outbound: tx_to_outbound.clone(),
                rx_from_inbound: Arc::new(Mutex::new(inbound_rx)),
                logger: logger.clone(),
                ecdsa_peer_id_to_libp2p_id: ecdsa_peer_id_to_libp2p_id.clone(),
            },
        );
    }

    let bind_ip = config.bind_ip;

    let mut ips_to_bind_to = vec![bind_ip];

    if let IpAddr::V6(v6_addr) = bind_ip {
        if v6_addr.is_loopback() {
            ips_to_bind_to.push(IpAddr::from_str("127.0.0.1").unwrap());
        } else {
            ips_to_bind_to.push(IpAddr::from_str("0.0.0.0").unwrap());
        }
    } else {
        if bind_ip.is_loopback() {
            ips_to_bind_to.push(IpAddr::from_str("::1").unwrap());
        } else {
            ips_to_bind_to.push(IpAddr::from_str("::").unwrap());
        }
    }

    for addr in ips_to_bind_to {
        let ip_label = if addr.is_ipv4() { "ip4" } else { "ip6" };
        swarm.listen_on(format!("/{ip_label}/{addr}/udp/{}/quic-v1", config.bind_port).parse()?)?;
        swarm.listen_on(format!("/{ip_label}/{addr}/tcp/{}", config.bind_port).parse()?)?;
    }

    // Dial all bootnodes
    for bootnode in &config.bootnodes {
        swarm.dial(
            DialOpts::unknown_peer_id()
                .address(bootnode.clone())
                .build(),
        )?;
    }

    let worker = async move {
        let span = tracing::debug_span!("network_worker");
        let _enter = span.enter();
        let service = NetworkServiceWithoutSwarm {
            logger: &logger,
            inbound_mapping: &inbound_mapping,
            ecdsa_peer_id_to_libp2p_id,
            role_key: &role_key,
            span: tracing::debug_span!(parent: &span, "network_service"),
        };
        loop {
            select! {
                // Setup outbound channel
                Some(msg) = rx_to_outbound.recv() => {
                    service.with_swarm(&mut swarm).handle_intra_node_payload(msg);
                }
                event = swarm.select_next_some() => {
                    service.with_swarm(&mut swarm).handle_swarm_event(event).await;
                }
            }
        }
    };

    let spawn_handle = spawn(worker);
    Ok((handles_ret, spawn_handle))
}
