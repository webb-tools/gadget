// ================= Common ======================== //
pub const DFNS_CGGMP21_KEYGEN_PROTOCOL_NAME: &str = "/webb-tools/dfns-cggmp21/keygen/1";
pub const DFNS_CGGMP21_SIGNING_PROTOCOL_NAME: &str = "/webb-tools/dfns-cggmp21/signing/1";

// ============= Signing Protocol ======================= //

pub mod signing_worker {
    use std::time::Duration;

    // the maximum number of tasks that the work manager tries to assign
    pub const MAX_RUNNING_TASKS: usize = 2;

    // the maximum number of tasks that can be enqueued,
    // enqueued here implies not actively running but listening for messages
    pub const MAX_ENQUEUED_TASKS: usize = 10;

    // How often to poll the jobs to check completion status
    pub const JOB_POLL_INTERVAL: Duration = Duration::from_millis(500);
}

// ============= Keygen Protocol ======================= //

pub mod keygen_worker {
    /// the maximum number of tasks that the work manager tries to assign
    /// at any given time for the keygen protocol.
    pub const MAX_RUNNING_TASKS: usize = 2;
    /// the maximum number of tasks that can be enqueued.
    pub const MAX_ENQUEUED_TASKS: usize = 10;
}
