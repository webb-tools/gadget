#[cfg(not(feature = "wasm"))]
use gadget_io::SupportedChains;
use tracing_subscriber::fmt::SubscriberBuilder;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(not(feature = "wasm"))]
use {
    crate::shell::ShellNodeInput,
    gadget_common::prelude::{DebugLogger, KeystoreBackend},
    gadget_core::job_manager::SendFuture,
    gadget_io::{defaults, ShellTomlConfig},
    structopt::StructOpt,
    tangle_subxt::tangle_testnet_runtime::api::jobs::events::job_refunded::RoleType,
};

#[cfg(not(feature = "wasm"))]
pub fn keystore_from_base_path(
    base_path: &std::path::Path,
    chain: SupportedChains,
    keystore_password: Option<String>,
) -> crate::KeystoreConfig {
    crate::KeystoreConfig::Path {
        path: base_path
            .join("chains")
            .join(chain.to_string())
            .join("keystore"),
        password: keystore_password.map(|s| s.into()),
    }
}

/// Runs a shell for a given protocol.
#[cfg(not(feature = "wasm"))]
pub async fn run_shell_for_protocol<
    KBE: KeystoreBackend,
    T: FnOnce(ShellNodeInput<KBE>) -> F,
    F,
    T2: FnOnce() -> F2,
    F2: SendFuture<'static, KBE>,
>(
    role_types: Vec<RoleType>,
    n_protocols: usize,
    keystore_backend: T2,
    executor: T,
) -> color_eyre::Result<()>
where
    F: SendFuture<'static, ()>,
{
    let args = std::env::args();
    println!("Args: {args:?}");
    let config = ShellTomlConfig::from_iter_safe(args);

    if config.is_err() {
        return Err(color_eyre::Report::msg(format!(
            "Failed to parse shell config: {config:?}"
        )));
    }

    let config = config.unwrap();
    let keystore_backend = keystore_backend().await;
    setup_shell_logger(config.verbose, config.pretty, "gadget")?;
    let keystore =
        keystore_from_base_path(&config.base_path, config.chain, config.keystore_password);

    let logger = DebugLogger {
        id: "test".to_string(),
    };
    logger.info("Starting shell with config: {config:?}");

    let (node_input, network_handle) = crate::generate_node_input(crate::ShellConfig {
        keystore_backend,
        role_types,
        keystore,
        subxt: crate::SubxtConfig {
            endpoint: config.url,
        },
        base_path: config.base_path,
        bind_ip: config.bind_ip,
        bind_port: config.bind_port,
        bootnodes: config.bootnodes,
        node_key: hex::decode(
            config
                .node_key
                .unwrap_or_else(|| hex::encode(defaults::generate_node_key())),
        )?
        .try_into()
        .map_err(|_| {
            color_eyre::eyre::eyre!("Invalid node key length, expect 32 bytes hex string")
        })?,
        n_protocols,
    })
    .await?;

    let protocol_future = gadget_io::tokio::task::spawn(executor(node_input));
    let ctrlc_future = gadget_io::tokio::signal::ctrl_c();

    gadget_io::tokio::select! {
        res0 = protocol_future => {
            Err(color_eyre::Report::msg(format!("Protocol future unexpectedly finished: {res0:?}")))
        },

        res1 = network_handle => {
            Err(color_eyre::Report::msg(format!("Networking future unexpectedly finished: {res1:?}")))
        },

        _ = ctrlc_future => {
            Ok(())
        }
    }
}

/// Sets up the logger for the shell-sdk, based on the verbosity level passed in.
pub fn setup_shell_logger(verbose: i32, pretty: bool, filter: &str) -> color_eyre::Result<()> {
    use tracing::Level;
    let log_level = match verbose {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        _ => Level::TRACE,
    };
    let env_filter =
        EnvFilter::from_default_env().add_directive(format!("{filter}={log_level}").parse()?);
    let logger = tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_line_number(false)
        .without_time()
        .with_max_level(log_level)
        .with_env_filter(env_filter);
    if pretty {
        let _ = logger.pretty().try_init();
    } else {
        let _ = logger.compact().try_init();
    }

    //let _ = env_logger::try_init();

    Ok(())
}
pub fn setup_log() {
    let _ = SubscriberBuilder::default()
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init();

    std::panic::set_hook(Box::new(|info| {
        log::error!(target: "gadget", "Panic occurred: {info:?}");
    }));
}
