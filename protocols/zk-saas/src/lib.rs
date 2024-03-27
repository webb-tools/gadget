use crate::network::ZkNetworkService;
use crate::protocol::ZkJobAdditionalParams;
use async_trait::async_trait;
use gadget_common::client::{ClientWithApi, JobsClient, PalletSubmitter};
use gadget_common::debug_logger::DebugLogger;
use gadget_common::full_protocol::SharedOptional;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use gadget_common::{generate_protocol, Error};
use mpc_net::prod::RustlsCertificate;
use network::ZkProtocolNetworkConfig;
use protocol_macros::protocol;
use sp_core::Pair;
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, RootCertStore};

pub mod network;
pub mod protocol;

generate_protocol!(
    "ZK-Protocol",
    ZkProtocol,
    ZkJobAdditionalParams,
    protocol::generate_protocol_from,
    protocol::create_next_job,
    jobs::JobType::ZkSaaSPhaseTwo(_),
    roles::RoleType::ZkSaaS(roles::zksaas::ZeroKnowledgeRoleType::ZkSaaSGroth16)
);

pub async fn create_zk_network<KBE: KeystoreBackend>(
    config: ZkProtocolNetworkConfig<KBE>,
) -> Result<ZkNetworkService, Error> {
    let our_identity = RustlsCertificate {
        cert: Certificate(config.public_identity_der.clone()),
        private_key: PrivateKey(config.private_identity_der.clone()),
    };

    if let Some(addr) = &config.king_bind_addr {
        ZkNetworkService::new_king(config.key_store.pair().public(), *addr, our_identity).await
    } else {
        let king_addr = config
            .client_only_king_addr
            .expect("King address must be specified if king bind address is not specified");

        let mut king_certs = RootCertStore::empty();
        king_certs
            .add(&Certificate(
                config
                    .client_only_king_public_identity_der
                    .clone()
                    .expect("The client must specify the identity of the king"),
            ))
            .map_err(|err| Error::InitError {
                err: err.to_string(),
            })?;

        ZkNetworkService::new_client(
            king_addr,
            config.key_store.pair().public(),
            our_identity,
            king_certs,
        )
        .await
    }
}

generate_setup_and_run_command!(ZkProtocol);
