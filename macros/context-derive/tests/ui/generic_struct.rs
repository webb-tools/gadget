use gadget_sdk::config::{GadgetConfiguration, StdGadgetConfiguration};
use gadget_sdk::contexts::{
    EVMProviderContext, KeystoreContext, ServicesContext, TangleClientContext,
};

#[derive(KeystoreContext, EVMProviderContext, TangleClientContext, ServicesContext)]
#[allow(dead_code)]
struct MyContext<T: Send + Sync, U: Send + Sync> {
    foo: T,
    bar: U,
    #[config]
    sdk_config: StdGadgetConfiguration,
    #[call_id]
    call_id: Option<u64>,
}

#[allow(dead_code)]
fn main() {
    let body = async {
        let ctx = MyContext {
            foo: "bar".to_string(),
            bar: 42,
            sdk_config: GadgetConfiguration::default(),
            call_id: None,
        };
        let _keystore = ctx.keystore();
        let _evm_provider = ctx.evm_provider().await.unwrap();
        let tangle_client = ctx.tangle_client().await.unwrap();
        let _services = ctx.current_service_operators(&tangle_client).await.unwrap();
    };

    drop(body);
}
