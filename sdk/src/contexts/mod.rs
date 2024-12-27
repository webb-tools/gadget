//! A set of traits and utilities that provide a common interface for interacting with the Gadget SDK.
//!
//! Usually, when you need access to the SDK, you will need to pass the Context to your jobs/functions. In your code, you will create a struct that encapsulates all the things that you would need from outside world from your job.
//! for example, if you need to interact with the network, you will need to have a network client in your struct. If you need to interact with the database storage, you will need to have a db client in your struct. And so on.
//!
//! This module provides a set of traits that you can implement for your struct to make it a context-aware struct by adding new functionalities to it.
//!
//! # Example
//!
//! ```rust,no_run
//! use gadget_context_derive::TangleClientContext;
//! use gadget_sdk::config::StdGadgetConfiguration;
//! use gadget_sdk::contexts::KeystoreContext;
//! use gadget_sdk::event_listener::tangle::jobs::{
//!     services_post_processor, services_pre_processor,
//! };
//! use gadget_sdk::event_listener::tangle::TangleEventListener;
//! use gadget_sdk::job;
//! use gadget_sdk::tangle_subxt::tangle_testnet_runtime::api::services::events::JobCalled;
//!
//! // This your struct that encapsulates all the things you need from outside world.
//! // By deriving KeystoreContext, you can now access the keystore client from your struct.
//! #[derive(Clone, Debug, KeystoreContext, TangleClientContext)]
//! struct MyContext {
//!     foo: String,
//!     bar: u64,
//!     #[config]
//!     sdk_config: StdGadgetConfiguration,
//!     #[call_id]
//!     call_id: Option<u64>,
//! }
//!
//! #[job(
//!     id = 0,
//!     params(who),
//!     result(_),
//!     event_listener(
//!         listener = TangleEventListener<MyContext, JobCalled>,
//!         pre_processor = services_pre_processor,
//!         post_processor = services_post_processor,
//!     )
//! )]
//! async fn my_job(who: String, ctx: MyContext) -> Result<String, std::convert::Infallible> {
//!     // Access the keystore client from the context.
//!     let keystore = ctx.keystore();
//!     // Do something with the keystore client.
//!     // ...
//!     Ok(format!("Hello, {}!", who))
//! }
//! ```

// derives
pub use gadget_context_derive::*;
pub use num_bigint::BigInt;

// A macro that takes an arbitrary mod, like "eigenlayer", then writes that as well as a line saying "pub use eigenlayer::*;" to the file.
// This way, we can easily add new modules to the SDK without having to manually import each time
macro_rules! create_module_derive {
    ($module:ident) => {
        mod $module;
        pub use $module::*;
    };
}

create_module_derive!(eigenlayer);
create_module_derive!(evm_provider);
create_module_derive!(gossip_network);
create_module_derive!(keystore);
create_module_derive!(services);
create_module_derive!(tangle_client);
