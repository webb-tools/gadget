use gadget_blueprint_proc_macro::job;

#[job(params(n, vec), result(Vec<u8>, String))]
fn keygen(n: u16, vec: Vec<u8>) -> Result<(Vec<u8>, String), String> {
    let _ = (n, vec);
    Err(String::new())
}

fn main() {
    println!("{KEYGEN_JOB_DEF}");
}
