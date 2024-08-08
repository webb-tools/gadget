use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::GadgetBinary;

#[derive(Debug)]
pub struct NativeGithubMetadata {
    pub git: String,
    pub tag: String,
    pub owner: String,
    pub repo: String,
    pub gadget_binaries: Vec<GadgetBinary>,
    pub blueprint_id: u64,
}
