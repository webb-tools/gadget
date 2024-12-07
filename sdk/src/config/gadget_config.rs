use super::*;
use crate::keystore::backend::GenericKeyStore;
#[cfg(any(feature = "std", feature = "wasm"))]
use crate::keystore::BackendExt;
#[cfg(any(feature = "std", feature = "wasm"))]
use crate::keystore::TanglePairSigner;
use crate::network::setup::NetworkConfig;
use crate::utils::test_utils::get_client;
use alloc::string::{String, ToString};
use core::fmt::Debug;
use core::net::IpAddr;
use eigensdk::crypto_bls;
use libp2p::Multiaddr;
use protocol::TangleInstanceSettings;
use std::path::PathBuf;

/// Gadget environment using the `parking_lot` RwLock.
#[cfg(feature = "std")]
pub type StdGadgetConfiguration = GadgetConfiguration<parking_lot::RawRwLock>;

/// Gadget environment.
#[non_exhaustive]
pub struct GadgetConfiguration<RwLock: lock_api::RawRwLock> {
    /// HTTP RPC endpoint for host network.
    pub http_rpc_endpoint: String,
    /// WS RPC endpoint for host network.
    pub ws_rpc_endpoint: String,
    /// Keystore URI
    ///
    /// * In Memory: `file::memory:` or `:memory:`
    /// * Filesystem: `file:/path/to/keystore` or `file:///path/to/keystore`
    pub keystore_uri: String,
    /// Data directory exclusively for this gadget
    ///
    /// This will be `None` if the blueprint manager was not provided a base directory.
    pub data_dir: Option<PathBuf>,
    /// The list of bootnodes to connect to
    pub bootnodes: Vec<Multiaddr>,
    /// The Current Environment is for the `PreRegistration` of the Gadget
    ///
    /// The gadget will now start in the Registration mode and will try to register the current operator on that blueprint
    /// There is no Service ID for this mode, since we need to register the operator first on the blueprint.
    ///
    /// If this is set to true, the gadget should do some work and register the operator on the blueprint.
    pub is_registration: bool,
    /// Whether to skip the registration process
    pub skip_registration: bool,
    /// The type of protocol the gadget is executing on.
    pub protocol: Protocol,
    /// Protocol-specific settings
    pub protocol_specific: ProtocolSpecificSettings,
    /// The Port of the Network that will be interacted with
    pub target_port: u16,
    /// The Address of the Network that will be interacted with
    pub target_addr: IpAddr,
    /// Whether the network being targeted uses a secure URL
    pub use_secure_url: bool,
    /// Specifies custom tracing span for the gadget
    pub span: tracing::Span,
    /// Whether the gadget is in test mode
    pub test_mode: bool,
    pub(crate) _lock: core::marker::PhantomData<RwLock>,
}

impl<RwLock: lock_api::RawRwLock> Debug for GadgetConfiguration<RwLock> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GadgetConfiguration")
            .field("http_rpc_endpoint", &self.http_rpc_endpoint)
            .field("ws_rpc_endpoint", &self.ws_rpc_endpoint)
            .field("keystore_uri", &self.keystore_uri)
            .field("data_dir", &self.data_dir)
            .field("bootnodes", &self.bootnodes)
            .field("is_registration", &self.is_registration)
            .field("skip_registration", &self.skip_registration)
            .field("protocol", &self.protocol)
            .field("protocol_specific", &self.protocol_specific)
            .field("bind_port", &self.target_port)
            .field("bind_addr", &self.target_addr)
            .field("test_mode", &self.test_mode)
            .finish()
    }
}

impl<RwLock: lock_api::RawRwLock> Clone for GadgetConfiguration<RwLock> {
    fn clone(&self) -> Self {
        Self {
            http_rpc_endpoint: self.http_rpc_endpoint.clone(),
            ws_rpc_endpoint: self.ws_rpc_endpoint.clone(),
            keystore_uri: self.keystore_uri.clone(),
            data_dir: self.data_dir.clone(),
            bootnodes: self.bootnodes.clone(),
            is_registration: self.is_registration,
            skip_registration: self.skip_registration,
            protocol: self.protocol,
            protocol_specific: self.protocol_specific,
            target_port: self.target_port,
            target_addr: self.target_addr,
            use_secure_url: self.use_secure_url,
            span: self.span.clone(),
            test_mode: self.test_mode,
            _lock: core::marker::PhantomData,
        }
    }
}

// Useful for quick testing
impl<RwLock: lock_api::RawRwLock> Default for GadgetConfiguration<RwLock> {
    fn default() -> Self {
        Self {
            http_rpc_endpoint: "http://localhost:9944".to_string(),
            ws_rpc_endpoint: "ws://localhost:9944".to_string(),
            keystore_uri: "file::memory:".to_string(),
            data_dir: None,
            bootnodes: Vec::new(),
            is_registration: false,
            skip_registration: false,
            protocol: Protocol::Tangle,
            protocol_specific: ProtocolSpecificSettings::Tangle(TangleInstanceSettings {
                blueprint_id: 0,
                service_id: Some(0),
            }),
            target_port: 0,
            target_addr: core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 1)),
            use_secure_url: false,
            span: tracing::Span::current(),
            test_mode: true,
            _lock: core::marker::PhantomData,
        }
    }
}

impl<RwLock: lock_api::RawRwLock> GadgetConfiguration<RwLock> {
    /// Returns a libp2p-friendly identity keypair.
    pub fn libp2p_identity(&self) -> Result<libp2p::identity::Keypair, Error> {
        let ed25519 = *self.first_ed25519_signer()?.signer();
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(ed25519.seed())
            .map_err(|err| Error::ConfigurationError(err.to_string()))?;
        Ok(keypair)
    }

    /// Returns a new `NetworkConfig` for the current environment.
    pub fn libp2p_network_config<T: Into<String>>(
        &self,
        network_name: T,
    ) -> Result<NetworkConfig, Error> {
        let network_identity = self.libp2p_identity()?;

        let my_ecdsa_key = self.first_ecdsa_signer()?;
        let network_config = NetworkConfig::new_service_network(
            network_identity,
            my_ecdsa_key.signer().clone(),
            self.bootnodes.clone(),
            self.target_port,
            network_name,
        );

        Ok(network_config)
    }
    /// Loads the `KeyStore` from the current environment.
    ///
    /// # Errors
    ///
    /// This function will return an error if the keystore URI is unsupported.
    pub fn keystore(&self) -> Result<GenericKeyStore<RwLock>, Error> {
        #[cfg(feature = "std")]
        use crate::keystore::backend::fs::FilesystemKeystore;
        use crate::keystore::backend::{mem::InMemoryKeystore, GenericKeyStore};

        match self.keystore_uri.as_str() {
            uri if uri == "file::memory:" || uri == ":memory:" => {
                Ok(GenericKeyStore::Mem(InMemoryKeystore::new()))
            }
            #[cfg(feature = "std")]
            uri if uri.starts_with("file:") || uri.starts_with("file://") => {
                let path = uri
                    .trim_start_matches("file://")
                    .trim_start_matches("file:");
                Ok(GenericKeyStore::Fs(FilesystemKeystore::open(path)?))
            }
            otherwise => Err(Error::UnsupportedKeystoreUri(otherwise.to_string())),
        }
    }

    /// Returns the first Sr25519 signer keypair from the keystore.
    ///
    /// # Errors
    ///
    /// * No sr25519 keypair is found in the keystore.
    /// * The keypair seed is invalid.
    #[doc(alias = "sr25519_signer")]
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn first_sr25519_signer(&self) -> Result<TanglePairSigner<sp_core::sr25519::Pair>, Error> {
        self.keystore()?.sr25519_key().map_err(Error::Keystore)
    }

    /// Returns the first ECDSA signer keypair from the keystore.
    ///
    /// # Errors
    ///
    /// * No ECDSA keypair is found in the keystore.
    /// * The keypair seed is invalid.
    #[doc(alias = "ecdsa_signer")]
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn first_ecdsa_signer(&self) -> Result<TanglePairSigner<sp_core::ecdsa::Pair>, Error> {
        self.keystore()?.ecdsa_key().map_err(Error::Keystore)
    }

    /// Returns the first ED25519 signer keypair from the keystore.
    ///
    /// # Errors
    ///
    /// * No ED25519 keypair is found in the keystore.
    /// * The keypair seed is invalid.
    #[doc(alias = "ed25519_signer")]
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn first_ed25519_signer(&self) -> Result<TanglePairSigner<sp_core::ed25519::Pair>, Error> {
        self.keystore()?.ed25519_key().map_err(Error::Keystore)
    }

    /// Returns the first BLS BN254 signer keypair from the keystore.
    ///
    /// # Errors
    ///
    /// This function will return an error if no BLS BN254 keypair is found in the keystore.
    #[doc(alias = "bls_bn254_signer")]
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub fn first_bls_bn254_signer(&self) -> Result<crypto_bls::BlsKeyPair, Error> {
        self.keystore()?.bls_bn254_key().map_err(Error::Keystore)
    }

    /// Returns whether the gadget should run in registration mode.
    #[must_use]
    pub const fn should_run_registration(&self) -> bool {
        self.is_registration
    }

    /// Returns a new [`subxt::OnlineClient`] for Tangle.
    ///
    /// When the [`Protocol`] field of the [`GadgetConfiguration`] is:
    /// - `Tangle`: Creates a [`TangleClient`](crate::clients::tangle::runtime::TangleClient) from
    ///   the RPC endpoints provided in the [`GadgetConfiguration`].
    /// - Any other protocol: Creates a [`TangleClient`](crate::clients::tangle::runtime::TangleClient) from
    ///   the provided bind address and port (assuming that address targets Tangle - fails otherwise).
    ///
    /// # Errors
    /// This function will return an error if we are unable to connect to the Tangle RPC endpoint.
    #[cfg(any(feature = "std", feature = "wasm"))]
    pub async fn client(&self) -> Result<crate::clients::tangle::runtime::TangleClient, Error> {
        match self.protocol {
            Protocol::Tangle => get_client(&self.ws_rpc_endpoint, &self.http_rpc_endpoint)
                .await
                .map_err(|err| Error::BadRpcConnection(err.to_string())),
            _ => {
                // If not using the Tangle protocol, attempt to create client with target endpoint
                get_client(&self.target_endpoint_ws(), &self.target_endpoint_http())
                    .await
                    .map_err(|err| Error::BadRpcConnection(err.to_string()))
            }
        }
    }

    /// Returns the HTTP endpoint string from the bind address and bind port specified in the [`GadgetConfiguration`].
    ///
    /// # Note
    /// This endpoint is *not* the same as the WS RPC endpoint in the [`GadgetConfiguration`]. This is the target endpoint
    /// rather than the endpoint for the network that matches the specified [`Protocol`].
    pub fn target_endpoint_http(&self) -> String {
        let base = match self.use_secure_url {
            true => "https",
            false => "http",
        };
        format!("{base}://{}:{}", self.target_addr, self.target_port)
    }

    /// Returns the WS endpoint string from the bind address and bind port specified in the [`GadgetConfiguration`].
    ///
    /// # Note
    /// This endpoint is *not* the same as the HTTP RPC endpoint in the [`GadgetConfiguration`]. This is the target endpoint
    /// rather than the endpoint for the network that matches the specified [`Protocol`].
    pub fn target_endpoint_ws(&self) -> String {
        let base = match self.use_secure_url {
            true => "wss",
            false => "ws",
        };
        format!("{base}://{}:{}", self.target_addr, self.target_port)
    }

    /// Only relevant if this is a Tangle protocol.
    pub fn service_id(&self) -> Option<u64> {
        let tangle_settings = self.protocol_specific.tangle().ok()?;
        let TangleInstanceSettings { service_id, .. } = tangle_settings;
        *service_id
    }
}
