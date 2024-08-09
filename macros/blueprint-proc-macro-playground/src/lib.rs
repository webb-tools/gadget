#![allow(dead_code)]

use gadget_sdk::{job, registration_hook, report, request_hook};

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidKeygen,
    InvalidSignature,
    InvalidRefresh,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            Error::InvalidKeygen => "Invalid Keygen",
            Error::InvalidSignature => "Invalid Signature",
            Error::InvalidRefresh => "Invalid Refresh",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for Error {}
pub struct MyContext;

// ==================
//       Jobs
// ==================

/// Simple Threshold (t) Keygen Job for n parties.
#[job(id = 0, params(n, t), result(_), verifier(evm = "KeygenContract"))]
pub fn keygen(ctx: &MyContext, n: u16, t: u16) -> Result<Vec<u8>, Error> {
    let _ = (n, t, ctx);
    Ok(vec![0; 33])
}

/// Sign a message using a key generated by the keygen job.
#[job(id = 1, params(keygen_id, data), result(_))]
pub async fn sign(keygen_id: u64, data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let _ = (keygen_id, data);
    Ok(vec![0; 65])
}

#[job(id = 2, params(keygen_id, new_t), result(_))]
pub fn refresh(keygen_id: u64, new_t: Option<u8>) -> Result<Vec<u64>, Error> {
    let _ = (keygen_id, new_t);
    Ok(vec![0; 33])
}

/// Say hello to someone or the world.
#[job(id = 3, params(who), result(_))]
pub fn say_hello(who: Option<String>) -> Result<String, Error> {
    match who {
        Some(who) => Ok(format!("Hello, {}!", who)),
        None => Ok("Hello, World!".to_string()),
    }
}

// ==================
//       Hooks
// ==================

#[registration_hook(evm = "RegistrationContract")]
pub fn on_register(pubkey: Vec<u8>);

#[request_hook(evm = "RequestContract")]
pub fn on_request(nft_id: u64);

// ==================
//      Reports
// ==================

/// Report function for the keygen job.
#[report(
    job_id = 0,
    params(n, t, msgs),
    result(_),
    report_type = "job",
    verifier(evm = "KeygenContract")
)]
fn report_keygen(n: u16, t: u16, msgs: Vec<Vec<u8>>) -> u32 {
    let _ = (n, t, msgs);
    0
}

#[report(
    params(uptime, response_time, error_rate),
    result(Vec<u8>),
    report_type = "qos",
    interval = 3600,
    metric_thresholds(uptime = 99, response_time = 1000, error_rate = 5)
)]
fn report_service_health(uptime: f64, response_time: u64, error_rate: f64) -> Vec<u8> {
    let mut issues = Vec::new();
    if uptime < 99.0 {
        issues.push(b"Low uptime".to_vec());
    }
    if response_time > 1000 {
        issues.push(b"High response time".to_vec());
    }
    if error_rate > 5.0 {
        issues.push(b"High error rate".to_vec());
    }
    issues.concat()
}

#[cfg(test)]
mod tests {
    #[test]
    fn generated_blueprint() {
        eprintln!("{}", super::KEYGEN_JOB_DEF);
        assert_eq!(super::KEYGEN_JOB_ID, 0);
        eprintln!("{}", super::REGISTRATION_HOOK);
    }
}
