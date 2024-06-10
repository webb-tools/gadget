use gadget_blueprint_proc_macro::job;

#[job(params(n, t), result(Vec<u8>))]
fn keygen(n: u16, vec: Vec<u8>) -> Result<Vec<u8>, String> {
    let _ = (n, vec);
    Err(String::new())
}

fn main() {}
