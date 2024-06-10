use gadget_blueprint_proc_macro::{blueprint, job};

#[job(params(n, t), result(_))]
pub fn keygen(n: u16, t: u8) -> Vec<u8> {
    let _ = (n, t);
    vec![0; 33]
}

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
    gadget: Native (
        runtime: Wasmtime,
        soruces: [],
    ),
}

#[cfg(test)]
mod tests {

    #[test]
    fn generated_blueprint() {
        eprintln!("{}", super::KEYGEN_JOB_DEF);
        eprintln!("{}", super::blueprint::BLUEPRINT);
    }
}
