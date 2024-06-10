use gadget_blueprint_proc_macro::job;

#[job(params(n, t), result(Vec<u8>))]
fn keygen(n: u16, t: u8) -> Vec<u8> {
    let _ = (n, t);
    Vec::new()
}

fn main() {
    println!("{KEYGEN_JOB_DEF}");
}
