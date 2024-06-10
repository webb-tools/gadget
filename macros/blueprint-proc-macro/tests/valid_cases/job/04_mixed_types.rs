use gadget_blueprint_proc_macro::job;

#[job(params(n, s), result(_))]
fn keygen(n: u16, s: String) -> Vec<u8> {
    let _ = (n, s);
    Vec::new()
}

fn main() {
    println!("{KEYGEN_JOB_DEF}");
}
