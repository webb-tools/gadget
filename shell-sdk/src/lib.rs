pub mod config;
pub mod entry;
pub mod keystore;
pub mod network;
#[cfg(not(feature = "wasm"))]
pub mod shell;
pub mod tangle;

pub use config::*;
pub use gadget_common::prelude::*;
pub use gadget_core::gadget::substrate::Client;
#[cfg(not(feature = "wasm"))]
pub use {
    shell::generate_node_input,
    entry::run_shell_for_protocol,
};

pub mod prelude {
    pub use crate::async_trait;
    pub use crate::protocol;
    pub use crate::BuiltExecutableJobWrapper;
    pub use crate::ClientWithApi;
    pub use crate::DebugLogger;
    pub use crate::ECDSAKeyStore;
    pub use crate::FullProtocolConfig;
    pub use crate::GadgetProtocolMessage;
    pub use crate::JobError;
    pub use crate::JobInitMetadata;
    pub use crate::JobsClient;
    pub use crate::KeystoreBackend;
    pub use crate::Mutex;
    pub use crate::Network;
    pub use crate::NodeInput;
    pub use crate::PalletSubmitter;
    pub use crate::ProtocolWorkManager;
    pub use crate::SendFuture;
    pub use crate::UnboundedReceiver;
    pub use crate::WorkManager;
    pub use crate::WorkManagerInterface;
    pub use gadget_common::full_protocol::SharedOptional;
    pub use gadget_common::prelude::InMemoryBackend;
    pub use gadget_common::tangle_runtime::AccountId32;
    pub use gadget_common::tangle_runtime::MaxAdditionalParamsLen;
    pub use gadget_common::tangle_runtime::MaxParticipants;
    pub use gadget_common::tangle_runtime::MaxSubmissionLen;
    pub use gadget_common::tangle_runtime::{jobs, RoleType};
    pub use gadget_common::Error;
    pub use gadget_common::{generate_protocol, generate_setup_and_run_command};
    pub use std::sync::Arc;
    pub use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::roles;

    pub use color_eyre;
    pub use pallet_dkg;
    pub use pallet_jobs;
    pub use pallet_jobs_rpc_runtime_api;
    pub use pallet_zksaas;
    pub use tangle_primitives;
    pub use tangle_subxt;
}

/// Should be put inside the main.rs file of the protocol repository
#[macro_export]
macro_rules! generate_shell_binary {
    ($entry_point:path, $keystore:path, $n_protocols:expr, $($role_type:expr),*) => {
        #[gadget_io::tokio::main]
        async fn main() -> color_eyre::Result<()> {
            $crate::run_shell_for_protocol(vec![$($role_type),*], $n_protocols, $keystore, $entry_point).await?;
            Ok(())
        }
    };
}
