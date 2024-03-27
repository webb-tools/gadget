use crate::client::{ClientWithApi, JobsClient};
use crate::debug_logger::DebugLogger;
use crate::gadget::message::GadgetProtocolMessage;
use crate::gadget::work_manager::WorkManager;
use crate::protocol::{AsyncProtocol, AsyncProtocolRemote};
use crate::tangle_runtime::*;
use crate::Error;
use async_trait::async_trait;
use gadget_core::gadget::substrate::{FinalityNotification, SubstrateGadgetModule};
use gadget_core::job::BuiltExecutableJobWrapper;
use gadget_core::job_manager::{PollMethod, ProtocolWorkManager, WorkManagerInterface};
use network::Network;
use parking_lot::RwLock;
use sp_core::{ecdsa, keccak_256, sr25519};
use std::sync::Arc;
use std::time::Duration;

pub mod message;
pub mod metrics;
pub mod network;
pub mod work_manager;

/// Used as a module to place inside the SubstrateGadget
pub struct Module<C, N, M> {
    protocol: M,
    network: N,
    job_manager: ProtocolWorkManager<WorkManager>,
    clock: Arc<RwLock<Option<u64>>>,
    _client: core::marker::PhantomData<C>,
}

const DEFAULT_MAX_ACTIVE_TASKS: usize = 4;
const DEFAULT_MAX_PENDING_TASKS: usize = 4;
const DEFAULT_POLL_INTERVAL: Option<Duration> = Some(Duration::from_millis(200));

#[derive(Debug)]
pub struct WorkManagerConfig {
    pub interval: Option<Duration>,
    pub max_active_tasks: usize,
    pub max_pending_tasks: usize,
}

impl Default for WorkManagerConfig {
    fn default() -> Self {
        WorkManagerConfig {
            interval: DEFAULT_POLL_INTERVAL,
            max_active_tasks: DEFAULT_MAX_ACTIVE_TASKS,
            max_pending_tasks: DEFAULT_MAX_PENDING_TASKS,
        }
    }
}

impl<C: ClientWithApi, N: Network, M: GadgetProtocol<C>> Module<C, N, M> {
    pub fn new(network: N, module: M, job_manager: ProtocolWorkManager<WorkManager>) -> Self {
        let clock = job_manager.utility.clock.clone();
        Module {
            protocol: module,
            job_manager,
            network,
            clock,
            _client: Default::default(),
        }
    }
}

pub struct JobInitMetadata {
    pub job_type:
        jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    pub role_type: roles::RoleType,
    /// This value only exists if this is a stage2 job
    pub phase1_job: Option<
        jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    >,
    pub participants_role_ids: Vec<ecdsa::Public>,
    pub task_id: <WorkManager as WorkManagerInterface>::TaskID,
    pub retry_id: <WorkManager as WorkManagerInterface>::RetryID,
    pub job_id: u64,
    pub now: <WorkManager as WorkManagerInterface>::Clock,
    pub at: [u8; 32],
}

#[async_trait]
impl<C: ClientWithApi, N: Network, M: GadgetProtocol<C>> SubstrateGadgetModule for Module<C, N, M> {
    type Error = Error;
    type ProtocolMessage = GadgetProtocolMessage;
    type Client = C;

    async fn get_next_protocol_message(&self) -> Option<Self::ProtocolMessage> {
        self.network.next_message().await
    }

    async fn process_finality_notification(
        &self,
        notification: FinalityNotification,
    ) -> Result<(), Self::Error> {
        let now: u64 = notification.number;
        *self.clock.write() = Some(now);
        self.protocol.logger().trace(format!(
            "Processing finality notification at block number {now}",
        ));

        let jobs = self
            .protocol
            .client()
            .query_jobs_by_validator(notification.hash, *self.protocol.account_id())
            .await?;

        self.protocol.logger().trace(format!(
            "Found {} potential job(s) for initialization",
            jobs.len()
        ));
        let mut relevant_jobs = Vec::new();

        for job in jobs {
            // Job is expired.
            if job.expiry < now {
                self.protocol.logger().trace(format!(
                    "[{}] The job requested for initialization is expired, skipping submission",
                    self.protocol.name()
                ));
                continue;
            }
            let role_type = match &job.job_type {
                jobs::JobType::DKGTSSPhaseOne(p) => roles::RoleType::Tss(p.role_type.clone()),
                jobs::JobType::DKGTSSPhaseTwo(p) => roles::RoleType::Tss(p.role_type.clone()),
                jobs::JobType::DKGTSSPhaseThree(p) => roles::RoleType::Tss(p.role_type.clone()),
                jobs::JobType::DKGTSSPhaseFour(p) => roles::RoleType::Tss(p.role_type.clone()),
                jobs::JobType::ZkSaaSPhaseOne(p) => roles::RoleType::ZkSaaS(p.role_type.clone()),
                jobs::JobType::ZkSaaSPhaseTwo(p) => roles::RoleType::ZkSaaS(p.role_type.clone()),
            };
            // Job is not for this role
            if !self.protocol.role_filter(role_type.clone()) {
                self.protocol.logger().trace(
                    format!(
                        "[{}] The job {} requested for initialization is not for this role {:?}, skipping submission",
                        self.protocol.name(),
                        job.job_id,
                        role_type
                    )
                );
                continue;
            }
            // Job is not for this phase
            if !self.protocol.phase_filter(job.job_type.clone()) {
                self.protocol.logger().trace(
                    format!(
                        "[{}] The job {} requested for initialization is not for this phase {:?}, skipping submission",
                        self.protocol.name(),
                        job.job_id,
                        job.job_type
                    )
                );
                continue;
            }

            let job_id = job.job_id;
            let task_id = job_id.to_be_bytes();
            let task_id = keccak_256(&task_id);
            if self.job_manager.job_exists(&task_id) {
                self.protocol.logger().trace(format!(
                    "[{}] The job {} is already running or enqueued, skipping submission",
                    self.protocol.name(),
                    job.job_id,
                ));
                continue;
            }

            let retry_id = self
                .job_manager
                .latest_retry_id(&task_id)
                .map(|r| r + 1)
                .unwrap_or(0);

            let is_phase_one = matches!(
                job.job_type,
                jobs::JobType::DKGTSSPhaseOne(_) | jobs::JobType::ZkSaaSPhaseOne(_)
            );

            let phase1_job = if is_phase_one {
                None
            } else {
                let phase_one_job_id = match &job.job_type {
                    jobs::JobType::DKGTSSPhaseOne(_) => unreachable!(),
                    jobs::JobType::ZkSaaSPhaseOne(_) => unreachable!(),
                    jobs::JobType::DKGTSSPhaseTwo(p) => p.phase_one_id,
                    jobs::JobType::DKGTSSPhaseThree(p) => p.phase_one_id,
                    jobs::JobType::DKGTSSPhaseFour(p) => p.phase_one_id,
                    jobs::JobType::ZkSaaSPhaseTwo(p) => p.phase_one_id,
                };
                let phase1_job = self
                        .protocol
                        .client()
                        .query_job_result(notification.hash, role_type.clone(), phase_one_job_id)
                        .await?
                        .ok_or_else(|| Error::ClientError {
                            err: format!("Corresponding phase one job {phase_one_job_id} not found for phase two job {job_id}"),
                        })?;
                Some(phase1_job.job_type)
            };

            let participants = match phase1_job {
                Some(ref j) => match j {
                    jobs::JobType::DKGTSSPhaseOne(p) => p.participants.0.clone(),
                    jobs::JobType::ZkSaaSPhaseOne(p) => p.participants.0.clone(),
                    _ => unreachable!(),
                },
                None => match &job.job_type {
                    jobs::JobType::DKGTSSPhaseOne(p) => p.participants.0.clone(),
                    jobs::JobType::ZkSaaSPhaseOne(p) => p.participants.0.clone(),
                    _ => unreachable!(),
                },
            };

            let participants_role_ids = {
                let mut out = Vec::new();
                for p in participants {
                    let maybe_role_key = self
                        .protocol
                        .client()
                        .query_restaker_role_key(notification.hash, sr25519::Public(p.0))
                        .await?;
                    if let Some(role_key) = maybe_role_key {
                        out.push(role_key);
                    } else {
                        self.protocol.logger().warn(format!(
                            "Participant {p} not found in the restaker registry",
                        ));
                    }
                }
                out
            };
            relevant_jobs.push(JobInitMetadata {
                role_type,
                job_type: job.job_type,
                phase1_job,
                participants_role_ids,
                task_id,
                retry_id,
                now,
                job_id,
                at: notification.hash,
            });
        }

        for relevant_job in relevant_jobs {
            let task_id = relevant_job.task_id;
            let retry_id = relevant_job.retry_id;
            self.protocol.logger().info(format!(
                "Creating job for task {task_id} with retry id {retry_id}",
                task_id = hex::encode(task_id),
                retry_id = retry_id
            ));
            match self
                .protocol
                .create_next_job(relevant_job, &self.job_manager)
                .await
            {
                Ok(params) => {
                    match self
                        .protocol
                        .create(0, now, retry_id, task_id, params)
                        .await
                    {
                        Ok(job) => {
                            let (remote, protocol) = job;
                            if let Err(err) = self.job_manager.push_task(
                                task_id,
                                false,
                                Arc::new(remote),
                                protocol,
                            ) {
                                self.protocol
                                    .process_error(
                                        Error::WorkManagerError { err },
                                        &self.job_manager,
                                    )
                                    .await;
                            }
                        }

                        Err(err) => {
                            self.protocol
                                .logger()
                                .error(format!("Failed to create async protocol: {err:?}"));
                        }
                    }
                }

                Err(Error::ParticipantNotSelected { id, reason }) => {
                    self.protocol.logger().debug(format!("Participant {id} not selected for job {task_id} with retry id {retry_id} because {reason}", id = id, task_id = hex::encode(task_id), retry_id = retry_id, reason = reason));
                }

                Err(err) => {
                    self.protocol
                        .logger()
                        .error(format!("Failed to generate job parameters: {err:?}"));
                }
            }
        }

        // Poll jobs on each finality notification if we're using manual polling.
        // This helps synchronize the actions of nodes in the network
        if self.job_manager.poll_method() == PollMethod::Manual {
            self.job_manager.poll();
        }

        Ok(())
    }

    async fn process_protocol_message(
        &self,
        message: Self::ProtocolMessage,
    ) -> Result<(), Self::Error> {
        self.job_manager
            .deliver_message(message)
            .map(|_| ())
            .map_err(|err| Error::WorkManagerError { err })
    }

    async fn process_error(&self, error: Self::Error) {
        self.protocol.process_error(error, &self.job_manager).await
    }
}

pub type Job = (AsyncProtocolRemote, BuiltExecutableJobWrapper);

#[async_trait]
pub trait GadgetProtocol<C: ClientWithApi>: AsyncProtocol + Send + Sync {
    /// Given an input of a valid and relevant job, return the parameters needed to start the async protocol
    /// Note: the parameters returned must be relevant to the `AsyncProtocol` implementation of this protocol
    ///
    /// In case the participant is not selected for some reason, return an [`Error::ParticipantNotSelected`]
    async fn create_next_job(
        &self,
        job: JobInitMetadata,
        work_manager: &ProtocolWorkManager<WorkManager>,
    ) -> Result<<Self as AsyncProtocol>::AdditionalParams, Error>;

    /// Process an error that may arise from the work manager, async protocol, or the executor
    async fn process_error(&self, error: Error, job_manager: &ProtocolWorkManager<WorkManager>);
    /// The account ID of this node. Jobs queried will be filtered by this account ID
    fn account_id(&self) -> &sr25519::Public;

    /// The Protocol Name.
    /// Used for logging and debugging purposes
    fn name(&self) -> String;
    /// Filter queried jobs by role type.
    /// ## Example
    ///
    /// ```rust,ignore
    /// fn role_filter(&self, role: RoleType) -> bool {
    ///   matches!(role, RoleType::Tss(ThresholdSignatureRoleType::ZengoGG20Secp256k1))
    /// }
    /// ```
    fn role_filter(&self, role: roles::RoleType) -> bool;

    /// Filter queried jobs by Job type & Phase.
    /// ## Example
    ///
    /// ```rust,ignore
    /// fn phase_filter(&self, job: JobType<AccountId, MaxParticipants, MaxSubmissionLen>) -> bool {
    ///   matches!(job, JobType::DKGTSSPhaseOne(_))
    /// }
    /// ```
    fn phase_filter(
        &self,
        job: jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>,
    ) -> bool;
    fn client(&self) -> JobsClient<C>;
    fn logger(&self) -> DebugLogger;
    fn get_work_manager_config(&self) -> WorkManagerConfig {
        Default::default()
    }
}
