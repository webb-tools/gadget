use crate::runtime::TangleConfig;
use crate::work_manager::TangleWorkManager;
use gadget_common::tangle_subxt::subxt::events::Events;
use gadget_common::WorkManagerInterface;

#[derive(Clone)]
pub struct TangleEvent {
    /// Finalized block number.
    pub number: u64,
    /// Finalized block header hash.
    pub hash: [u8; 32],
    /// Events
    pub events: Events<TangleConfig>,
}

pub struct TangleJobMetadata {
    pub task_id: <TangleWorkManager as WorkManagerInterface>::TaskID,
    pub retry_id: <TangleWorkManager as WorkManagerInterface>::RetryID,
    pub job_id: u64,
    pub now: <TangleWorkManager as WorkManagerInterface>::Clock,
    pub at: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SubxtConfig {
    /// The URL of the Tangle Node.
    pub endpoint: url::Url,
}
