pub mod config;
pub mod entry;
pub mod keystore;
pub mod shell;

pub use config::*;
pub use entry::run_shell_for_protocol;
pub use gadget_common::prelude::*;
pub use gadget_core::gadget::general::Client;
pub use gadget_sdk::network::setup::{start_p2p_network, NetworkConfig};
pub use shell::generate_node_input;

pub mod prelude {
    pub use crate::async_trait;
    pub use crate::protocol;
    pub use crate::BuiltExecutableJobWrapper;
    pub use crate::DebugLogger;
    pub use crate::ECDSAKeyStore;
    pub use crate::FullProtocolConfig;
    pub use crate::JobError;
    pub use crate::JobsClient;
    pub use crate::KeystoreBackend;
    pub use crate::Mutex;
    pub use crate::Network;
    pub use crate::NodeInput;
    pub use crate::ProtocolWorkManager;
    pub use crate::SendFuture;
    pub use crate::UnboundedReceiver;
    pub use crate::WorkManagerInterface;
    pub use gadget_common::full_protocol::SharedOptional;

    pub use gadget_common::prelude::InMemoryBackend;
    pub use gadget_common::tangle_runtime::AccountId32;
    pub use gadget_common::Error;
    pub use gadget_common::{generate_protocol, generate_setup_and_run_command};
    pub use std::sync::Arc;

    pub use color_eyre;
    pub use tangle_primitives;
    pub use tangle_subxt;
}
