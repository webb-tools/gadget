#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    unsafe_code,
    unstable_features,
    unused_qualifications,
    missing_docs,
    unused_results,
    clippy::exhaustive_enums
)]
//! Proc-macros for deriving Context Extensions from [`gadget-sdk`](https://crates.io/crates/gadget-sdk) crate.
use proc_macro::TokenStream;

/// Field information for the configuration field.
mod cfg;
/// Eigenlayer context extension implementation.
mod eigenlayer;
/// EVM Provider context extension implementation.
mod evm;
/// Keystore context extension implementation.
mod keystore;
/// Services context extension implementation.
mod services;
/// Tangle Subxt Client context extension implementation.
mod tangle;

const CONFIG_TAG_NAME: &str = "config";
const CONFIG_TAG_TYPE: &str = "gadget_sdk::config::GadgetConfiguration";
const CALL_ID_TAG_NAME: &str = "call_id";
const CALL_ID_TAG_TYPE: &str = "Option<u64>";

/// Derive macro for generating Context Extensions trait implementation for `KeystoreContext`.
#[proc_macro_derive(KeystoreContext, attributes(config))]
pub fn derive_keystore_context(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result =
        cfg::find_config_field(&input.ident, &input.data, CONFIG_TAG_NAME, CONFIG_TAG_TYPE)
            .map(|config_field| keystore::generate_context_impl(input, config_field));

    match result {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

/// Derive macro for generating Context Extensions trait implementation for `EVMProviderContext`.
#[proc_macro_derive(EVMProviderContext, attributes(config))]
pub fn derive_evm_provider_context(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result =
        cfg::find_config_field(&input.ident, &input.data, CONFIG_TAG_NAME, CONFIG_TAG_TYPE)
            .map(|config_field| evm::generate_context_impl(input, config_field));

    match result {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

/// Derive macro for generating Context Extensions trait implementation for `TangleClientContext`.
#[proc_macro_derive(TangleClientContext, attributes(config, call_id))]
pub fn derive_tangle_client_context(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result =
        cfg::find_config_field(&input.ident, &input.data, CONFIG_TAG_NAME, CONFIG_TAG_TYPE)
            .and_then(|res| {
                let call_id_field = cfg::find_config_field(
                    &input.ident,
                    &input.data,
                    CALL_ID_TAG_NAME,
                    CALL_ID_TAG_TYPE,
                )?;
                Ok((res, call_id_field))
            })
            .map(|(config_field, call_id_field)| {
                tangle::generate_context_impl(input, config_field, call_id_field)
            });

    match result {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

/// Derive macro for generating Context Extensions trait implementation for `ServicesContext`.
#[proc_macro_derive(ServicesContext, attributes(config))]
pub fn derive_services_context(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result =
        cfg::find_config_field(&input.ident, &input.data, CONFIG_TAG_NAME, CONFIG_TAG_TYPE)
            .map(|config_field| services::generate_context_impl(input, config_field));

    match result {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}

/// Derive macro for generating Context Extensions trait implementation for `EigenlayerContext`.
#[proc_macro_derive(EigenlayerContext, attributes(config))]
pub fn derive_eigenlayer_context(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let result =
        cfg::find_config_field(&input.ident, &input.data, CONFIG_TAG_NAME, CONFIG_TAG_TYPE)
            .map(|config_field| eigenlayer::generate_context_impl(input, config_field));

    match result {
        Ok(expanded) => TokenStream::from(expanded),
        Err(err) => TokenStream::from(err.to_compile_error()),
    }
}
