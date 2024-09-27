use gadget_sdk::config::StdGadgetConfiguration;
use gadget_sdk::ctx::{EVMProviderContext, KeystoreContext};

#[derive(KeystoreContext, EVMProviderContext)]
struct MyContext(String, #[config] StdGadgetConfiguration);

fn main() {
    let ctx = MyContext("bar".to_string(), Default::default());
    let _keystore = ctx.keystore();
    let _evm_provider = ctx.evm_provider();
}
