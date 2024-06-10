use gadget_blueprint_proc_macro::job;

#[job(params(n), result(Vec<u8> String))]
fn keygen(n: u16) -> (Vec<u8>, String) {
    (Vec::new(), String::new())
}

fn main() {}
