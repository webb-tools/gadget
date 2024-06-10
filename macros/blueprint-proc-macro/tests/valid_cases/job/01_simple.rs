use gadget_blueprint_proc_macro::job;

/// A simple job that generates a key of length `n`
#[job(params(n), result(Vec<u8>))]
fn keygen(n: u16) -> Vec<u8> {
    let _ = n;
    Vec::new()
}

fn main() {
    // Ensure the generated code exists
    println!("{KEYGEN_JOB_DEF}");
}
