use gadget_blueprint_proc_macro::job;
#[job(params(n), result(_))]
fn keygen(n: u16) -> Vec<u8> {
    let _ = n;
    Vec::new()
}

fn main() {
    println!("{KEYGEN_JOB_DEF}");
}
