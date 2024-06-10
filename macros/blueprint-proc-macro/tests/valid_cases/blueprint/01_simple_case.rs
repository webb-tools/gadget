use gadget_blueprint_proc_macro::blueprint;

blueprint! {
    metadata: (
        name: "My Service",
        version: "1.0.0",
        description: "My service description",
    ),
    jobs: [],
    registration_hook: Evm("0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97"),
    registration_params: [Uint8],
    request_hook: None,
    request_params: [],
    gadget: Wasm (
        runtime: Wasmtime,
        soruces: [],
    ),
}

fn main() {
    use blueprint::*;
    println!("{:?}", BLUEPRINT);
}
