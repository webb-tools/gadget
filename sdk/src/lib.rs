#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    missing_docs,
    rustdoc::broken_intra_doc_links,
    unused_results,
    clippy::all,
    clippy::pedantic,
    clippy::exhaustive_enums
)]
#![allow(dead_code)]
//! Gadget SDK

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Keystore Module
#[cfg(not(feature = "wasm"))]
pub mod keystore;

/// Metrics Module
// pub mod metrics;

/// Logging Module
pub mod logging;
/// Randomness generation module
#[cfg(not(feature = "wasm"))]
pub mod random;
