pub mod shared;
#[cfg(not(target_family = "wasm"))]
pub mod standard;
#[cfg(target_family = "wasm")]
pub mod wasm;

#[cfg(target_family = "wasm")]
pub use wasm::{
    keystore::{KeystoreConfig, KeystoreContainer, SubstrateKeystore},
    shell::{Opt, ShellTomlConfig, SupportedChains},
};

#[cfg(not(target_family = "wasm"))]
pub use standard::{
    keystore::{KeystoreConfig, KeystoreContainer, SubstrateKeystore},
    shell::{defaults, GadgetConfig, Opt, SupportedChains},
};

#[cfg(target_family = "wasm")]
pub use {tokio, wasm_bindgen_futures::spawn_local as spawn};

#[cfg(not(target_family = "wasm"))]
pub use {tokio, tokio::task::spawn};

#[cfg(target_family = "wasm")]
pub use wasmtimer::tokio as time;

#[cfg(not(target_family = "wasm"))]
pub use tokio::time;

#[cfg(not(target_family = "wasm"))]
pub fn log(s: &str) {
    println!("{}", s);
}

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(target_family = "wasm")]
pub fn into_js_error(err: impl std::error::Error) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}
