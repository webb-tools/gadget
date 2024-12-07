#![allow(unused_imports)]
use crate::test_ext::NAME_IDS;
use api::services::events::JobResultSubmitted;
use blueprint_manager::config::BlueprintManagerConfig;
use blueprint_manager::executor::BlueprintManagerHandle;
use gadget_io::{GadgetConfig, SupportedChains};
use gadget_sdk::clients::tangle::runtime::{TangleClient, TangleConfig};
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::sp_arithmetic::per_things::Percent;
pub use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::calls::types::call::{Args, Job};
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::calls::types::create_blueprint::Blueprint;
use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::calls::types::register::{Preferences, RegistrationArgs};
use gadget_sdk::keystore;
use gadget_sdk::keystore::backend::fs::FilesystemKeystore;
use gadget_sdk::keystore::backend::GenericKeyStore;
use gadget_sdk::keystore::{Backend, BackendExt, TanglePairSigner};
use libp2p::Multiaddr;
pub use log;
use sp_core::Pair as PairT;
use std::error::Error;
use std::ffi::OsStr;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use alloy_primitives::hex;
use cargo_toml::Manifest;
use color_eyre::eyre::eyre;
use subxt::tx::{Signer, TxProgress};
use subxt::utils::AccountId32;
use url::Url;
use uuid::Uuid;
use gadget_sdk::{error, info};

pub use cargo_tangle::deploy::Opts;
pub use gadget_sdk::logging::setup_log;

pub type InputValue = runtime_types::tangle_primitives::services::field::Field<AccountId32>;
pub type OutputValue = runtime_types::tangle_primitives::services::field::Field<AccountId32>;

pub mod anvil;
pub mod eigenlayer_test_env;
pub mod helpers;
pub mod mpc;
pub mod symbiotic_test_env;
pub mod sync;
pub mod tangle;
pub mod test_ext;
mod test_runner;

use anvil::ANVIL_PRIVATE_KEYS;
pub use gadget_sdk;
pub use gadget_sdk::ext::blueprint_serde::BoundedVec;
pub use tangle::transactions::{get_next_call_id, submit_job, wait_for_completion_of_tangle_job};
pub use tempfile;

pub type TestClient = TangleClient;

pub struct PerTestNodeInput<T> {
    instance_id: u64,
    bind_ip: IpAddr,
    bind_port: u16,
    bootnodes: Vec<Multiaddr>,
    verbose: u8,
    pretty: bool,
    #[allow(dead_code)]
    extra_input: T,
    http_rpc_url: Url,
    ws_rpc_url: Url,
}

/// Runs a test node using a top-down approach and invoking the blueprint manager to auto manage
/// execution of blueprints and their associated services for the test node.
pub async fn run_test_blueprint_manager<T: Send + Clone + AsRef<OsStr> + 'static>(
    input: PerTestNodeInput<T>,
) -> BlueprintManagerHandle {
    let name_lower = NAME_IDS[input.instance_id as usize].to_lowercase();

    let keystore_path = Path::new(&input.extra_input);

    let tmp_store = Uuid::new_v4().to_string();
    let keystore_uri = keystore_path.join(format!("keystores/{name_lower}/{tmp_store}/"));

    assert!(
        !keystore_uri.exists(),
        "Keystore URI cannot exist: {}",
        keystore_uri.display()
    );

    let data_dir = std::path::absolute(format!("./target/data/{name_lower}"))
        .expect("Failed to get current directory");

    let keystore_uri_normalized =
        std::path::absolute(keystore_uri.clone()).expect("Failed to resolve keystore URI");
    let keystore_uri_str = format!("file:{}", keystore_uri_normalized.display());

    inject_test_keys(
        &keystore_uri,
        KeyGenType::Tangle(input.instance_id as usize),
    )
    .await
    .expect("Failed to inject testing-related SR25519 keys");

    // Canonicalize to prove the directory exists
    let _ = keystore_uri_normalized
        .canonicalize()
        .expect("Failed to resolve keystore URI");

    let blueprint_manager_config = BlueprintManagerConfig {
        gadget_config: None,
        data_dir,
        keystore_uri: keystore_uri_str.clone(),
        verbose: input.verbose,
        pretty: input.pretty,
        instance_id: Some(NAME_IDS[input.instance_id as usize].to_string()),
        test_mode: true,
    };

    let gadget_config = GadgetConfig {
        bind_addr: input.bind_ip,
        bind_port: input.bind_port,
        http_rpc_url: input.http_rpc_url,
        ws_rpc_url: input.ws_rpc_url,
        bootnodes: input.bootnodes,
        keystore_uri: keystore_uri_str,
        keystore_password: None,
        chain: SupportedChains::LocalTestnet,
        verbose: input.verbose,
        pretty: input.pretty,
    };

    let shutdown_signal = futures::future::pending();

    match blueprint_manager::run_blueprint_manager(
        blueprint_manager_config,
        gadget_config,
        shutdown_signal,
    )
    .await
    {
        Ok(res) => res,
        Err(err) => {
            log::error!(target: "gadget", "Failed to run blueprint manager: {err}");
            panic!("Failed to run blueprint manager: {err}");
        }
    }
}

/// The possible keys to be generated when injecting keys in a keystore for testing.
///
/// - `Random`: A random key will be generated
/// - `Anvil`: Injects one of the premade Anvil key of the given index where that index is 0-9
/// - `Tangle`: Injects the premade Tangle key of the given index where that index is 0-4
///
/// # Errors
///
/// - If the given index is out of bounds for the specified type
/// - Random Key Generation Failure
/// - Generated Key Sanity Check Error
#[derive(Debug, Clone, Copy)]
pub enum KeyGenType {
    Random,
    Anvil(usize),
    Tangle(usize),
}

/// Adds keys for testing to the keystore.
///
/// # Arguments
///
/// - `keystore_path`: The path for the keystore.
/// - `key_gen_type`: The type of key to generate, specified by the [`KeyGenType`] enum.
///
/// # Key Generation
///
/// Depending on the [`KeyGenType`] provided:
/// - `Random`: Generates all random keys.
/// - `Anvil(index)`: Injects the pre-made Anvil ECDSA key from the 10 Anvil dev keys based on the provided index (0-9) and generates a random keys for each other key type
/// - `Tangle(index)`: Injects the pre-made Tangle ED25519, ECDSA, and SR25519 keys based on the provided index (0-4). Randomly generates BLS keys
///
/// # Errors
///
/// This function will return an error if:
/// - The keystore path cannot be created.
/// - Key generation fails for any reason (e.g., invalid seed, random generation failure).
/// - The given index is out of bounds for Anvil or Tangle key types.
///
/// # Returns
///
/// Returns `Ok(())` if the keys were successfully injected, otherwise returns an `Err`.
pub async fn inject_test_keys<P: AsRef<Path>>(
    keystore_path: P,
    key_gen_type: KeyGenType,
) -> color_eyre::Result<()> {
    let path = keystore_path.as_ref();
    tokio::fs::create_dir_all(path).await?;

    match key_gen_type {
        KeyGenType::Random => {
            inject_random_key(&keystore_path)?;
        }
        KeyGenType::Anvil(index) => {
            let private_key = ANVIL_PRIVATE_KEYS[index];
            inject_anvil_key(&keystore_path, private_key)?;
        }
        KeyGenType::Tangle(index) => {
            inject_tangle_key(&keystore_path, NAME_IDS[index])?;
        }
    }

    Ok(())
}

/// Injects the pre-made Anvil key of the given index where that index is 0-9
///
/// # Keys Generated
/// - `SR25519`: Random
/// - `ED25519`: Random
/// - `ECDSA`: Anvil Dev Key
/// - `BLS BN254`: Random
/// - `BLS381`: Random
///
/// # Errors
/// - Fails if the given index is out of bounds
/// - May fail if the keystore path cannot be created or accessed
fn inject_anvil_key<P: AsRef<Path>>(keystore_path: P, seed: &str) -> color_eyre::Result<()> {
    let keystore = GenericKeyStore::<parking_lot::RawRwLock>::Fs(FilesystemKeystore::open(
        keystore_path.as_ref(),
    )?);

    let seed_bytes = hex::decode(&seed[2..]).expect("Invalid hex seed");
    keystore
        .ecdsa_generate_new(Some(&seed_bytes))
        .map_err(|e| eyre!(e))?;
    keystore
        .bls_bn254_generate_new(None)
        .map_err(|e| eyre!(e))?;
    keystore.sr25519_generate_new(None).map_err(|e| eyre!(e))?;
    keystore.ed25519_generate_new(None).map_err(|e| eyre!(e))?;
    keystore.bls381_generate_new(None).map_err(|e| eyre!(e))?;

    Ok(())
}

/// Injects the pre-made Tangle keys of the given index where that index is 0-4
///
/// # Keys Generated
/// - `SR25519`: Tangle Dev Key
/// - `ED25519`: Tangle Dev Key
/// - `ECDSA`: Tangle Dev Key
/// - `BLS BN254`: Random
/// - `BLS381`: Random
///
/// # Indices
/// - 0: Alice
/// - 1: Bob
/// - 2: Charlie
/// - 3:Dave
/// - 4: Eve
///
/// # Errors
/// - Fails if the given index is out of bounds
/// - May fail if the keystore path cannot be created or accessed
fn inject_tangle_key<P: AsRef<Path>>(keystore_path: P, name: &str) -> color_eyre::Result<()> {
    let keystore = GenericKeyStore::<parking_lot::RawRwLock>::Fs(FilesystemKeystore::open(
        keystore_path.as_ref(),
    )?);

    let suri = format!("//{name}");

    let sr = sp_core::sr25519::Pair::from_string(&suri, None).expect("Should be valid SR keypair");
    let sr_seed = &sr.as_ref().secret.to_bytes();

    let ed = sp_core::ed25519::Pair::from_string(&suri, None).expect("Should be valid ED keypair");
    let ed_seed = &ed.seed();

    let ecdsa =
        sp_core::ecdsa::Pair::from_string(&suri, None).expect("Should be valid ECDSA keypair");
    let ecdsa_seed = ecdsa.seed();

    keystore
        .sr25519_generate_new(Some(sr_seed))
        .map_err(|e| eyre!(e))?;
    keystore
        .ed25519_generate_new(Some(ed_seed))
        .map_err(|e| eyre!(e))?;
    keystore
        .ecdsa_generate_new(Some(&ecdsa_seed))
        .map_err(|e| eyre!(e))?;
    keystore.bls381_generate_new(None).map_err(|e| eyre!(e))?;
    keystore
        .bls_bn254_generate_new(None)
        .map_err(|e| eyre!(e))?;

    // Perform sanity checks on conversions between secrets to ensure
    // consistency as the program executes
    let bytes: [u8; 64] = sr.as_ref().secret.to_bytes();
    let secret_key_again =
        keystore::sr25519::secret_from_bytes(&bytes).expect("Invalid SR25519 Bytes");
    assert_eq!(&bytes[..], &secret_key_again.to_bytes()[..]);

    let sr2 = TanglePairSigner::new(
        sp_core::sr25519::Pair::from_seed_slice(&bytes).expect("Invalid SR25519 keypair"),
    );

    let sr1_account_id: AccountId32 = AccountId32(sr.as_ref().public.to_bytes());
    let sr2_account_id: AccountId32 = sr2.account_id().clone();
    assert_eq!(sr1_account_id, sr2_account_id);

    match keystore.ecdsa_key() {
        Ok(ecdsa_key) => {
            assert_eq!(ecdsa_key.signer().seed(), ecdsa_seed);
        }
        Err(err) => {
            log::error!(target: "gadget", "Failed to load ecdsa key: {err}");
            panic!("Failed to load ecdsa key: {err}");
        }
    }

    match keystore.sr25519_key() {
        Ok(sr25519_key) => {
            assert_eq!(sr25519_key.signer().public().0, sr.public().0);
        }
        Err(err) => {
            log::error!(target: "gadget", "Failed to load sr25519 key: {err}");
            panic!("Failed to load sr25519 key: {err}");
        }
    }

    match keystore.ed25519_key() {
        Ok(ed25519_key) => {
            assert_eq!(ed25519_key.signer().public().0, ed.public().0);
        }
        Err(err) => {
            log::error!(target: "gadget", "Failed to load ed25519 key: {err}");
            panic!("Failed to load ed25519 key: {err}");
        }
    }

    Ok(())
}

/// Injects randomly generated keys into the keystore at the given path
///
/// # Keys Generated
/// - `SR25519` - Random
/// - `ED25519` - Random
/// - `ECDSA` - Random
/// - `BLS BN254` - Random
/// - `BLS381` - Random
///
/// # Errors
/// - May fail if the keystore path cannot be created or accessed
pub fn inject_random_key<P: AsRef<Path>>(keystore_path: P) -> color_eyre::Result<()> {
    let keystore = GenericKeyStore::<parking_lot::RawRwLock>::Fs(FilesystemKeystore::open(
        keystore_path.as_ref(),
    )?);
    keystore.sr25519_generate_new(None).map_err(|e| eyre!(e))?;
    keystore.ed25519_generate_new(None).map_err(|e| eyre!(e))?;
    keystore.ecdsa_generate_new(None).map_err(|e| eyre!(e))?;
    keystore
        .bls_bn254_generate_new(None)
        .map_err(|e| eyre!(e))?;
    keystore.bls381_generate_new(None).map_err(|e| eyre!(e))?;
    Ok(())
}

/// Returns the output of "git rev-parse --show-toplevel" to get the root of the git repository as a PathBuf.
/// If it's not in a git repo, default to return the current directory
pub fn get_blueprint_base_dir() -> PathBuf {
    let output = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .expect("Failed to run git command");

    if output.status.success() {
        let path = std::str::from_utf8(&output.stdout)
            .expect("Failed to convert output to string")
            .trim();
        PathBuf::from(path)
    } else {
        std::env::current_dir().expect("Failed to get current directory")
    }
}

pub fn read_cargo_toml_file<P: AsRef<Path>>(path: P) -> std::io::Result<Manifest> {
    let manifest = cargo_toml::Manifest::from_path(path).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to read Cargo.toml: {err}"),
        )
    })?;
    if manifest.package.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No package section found in Cargo.toml",
        ));
    }

    Ok(manifest)
}
