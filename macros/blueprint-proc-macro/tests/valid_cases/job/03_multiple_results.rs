use gadget_blueprint_proc_macro::job;

#[job(params(n), result(Vec<u8>, String))]
fn keygen(n: u16) -> (Vec<u8>, String) {
    let _ = n;
    (Vec::new(), String::new())
}

fn main() {
    println!("{KEYGEN_JOB_DEF}");
}
