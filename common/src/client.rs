use crate::debug_logger::DebugLogger;
use crate::tangle_runtime::*;
use async_trait::async_trait;
use auto_impl::auto_impl;
use gadget_core::gadget::substrate::{Client, FinalityNotification};
use sp_core::{ecdsa, ByteArray};
use sp_core::{sr25519, Pair};
use std::sync::Arc;
use tangle_subxt::subxt::{self, tx::TxPayload, OnlineClient};

pub struct JobsClient<C> {
    pub client: C,
    logger: DebugLogger,
    pallet_tx: Arc<dyn PalletSubmitter>,
}

impl<C: Clone> Clone for JobsClient<C> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            logger: self.logger.clone(),
            pallet_tx: self.pallet_tx.clone(),
        }
    }
}

pub async fn create_client<C: ClientWithApi>(
    client: C,
    logger: DebugLogger,
    pallet_tx: Arc<dyn PalletSubmitter>,
) -> Result<JobsClient<C>, crate::Error> {
    Ok(JobsClient {
        client,
        logger,
        pallet_tx,
    })
}

pub async fn exec_client_function<C: Clone, F, T>(client: &C, function: F) -> T
where
    for<'a> F: FnOnce(&'a C) -> T,
    C: Send + Sync + 'static,
    T: Send + 'static,
    F: Send + 'static,
{
    let client = client.clone();
    tokio::task::spawn_blocking(move || function(&client))
        .await
        .expect("Failed to spawn blocking task")
}

pub trait JobTypeExt {
    /// Checks if the job type is a phase one job.
    fn is_phase_one(&self) -> bool;
    /// Gets the participants for the job type, if applicable.
    fn get_participants(self) -> Option<Vec<AccountId32>>;
    /// Gets the threshold value for the job type, if applicable.
    fn get_threshold(self) -> Option<u8>;
    /// Gets the role associated with the job type.
    fn get_role_type(&self) -> roles::RoleType;
    /// Gets the phase one ID for phase two jobs, if applicable.
    fn get_phase_one_id(&self) -> Option<u64>;
    /// Gets the permitted caller for the job type, if applicable.
    fn get_permitted_caller(self) -> Option<AccountId32>;
}

pub trait PhaseResultExt {
    /// Gets the participants for the phase result, if applicable.
    fn participants(&self) -> Option<Vec<AccountId32>>;
    /// Gets the threshold value for the phase result, if applicable.
    fn threshold(&self) -> Option<u8>;
}

#[async_trait]
#[auto_impl(Arc)]
pub trait ClientWithApi: Client {
    /// Query jobs associated with a specific validator.
    ///
    /// This function takes a `validator` parameter of type `AccountId` and attempts
    /// to retrieve a list of jobs associated with the provided validator. If successful,
    /// it constructs a vector of `RpcResponseJobsData` containing information
    /// about the jobs and returns it as a `Result`.
    ///
    /// # Arguments
    ///
    /// * `validator` - The account ID of the validator whose jobs are to be queried.
    ///
    /// # Returns
    ///
    /// An optional vec of `RpcResponseJobsData` of jobs assigned to validator
    async fn query_jobs_by_validator(
        &self,
        at: [u8; 32],
        validator: AccountId32,
    ) -> Result<
        Option<
            Vec<
                jobs::RpcResponseJobsData<
                    AccountId32,
                    u64,
                    MaxParticipants,
                    MaxSubmissionLen,
                    MaxAdditionalParamsLen,
                >,
            >,
        >,
        crate::Error,
    >;
    /// Queries a job by its key and ID.
    ///
    /// # Arguments
    ///
    /// * `role_type` - The role of the job.
    /// * `job_id` - The ID of the job.
    ///
    /// # Returns
    ///
    /// An optional `RpcResponseJobsData` containing the account ID of the job.
    async fn query_job_by_id(
        &self,
        at: [u8; 32],
        role_type: roles::RoleType,
        job_id: u64,
    ) -> Result<
        Option<
            jobs::RpcResponseJobsData<
                AccountId32,
                u64,
                MaxParticipants,
                MaxSubmissionLen,
                MaxAdditionalParamsLen,
            >,
        >,
        crate::Error,
    >;

    /// Queries the result of a job by its role_type and ID.
    ///
    /// # Arguments
    ///
    /// * `role_type` - The role of the job.
    /// * `job_id` - The ID of the job.
    ///
    /// # Returns
    ///
    /// An `Option` containing the phase one result of the job, wrapped in an `PhaseResult`.
    async fn query_job_result(
        &self,
        at: [u8; 32],
        role_type: roles::RoleType,
        job_id: u64,
    ) -> Result<
        Option<
            jobs::PhaseResult<
                AccountId32,
                u64,
                MaxParticipants,
                MaxKeyLen,
                MaxDataLen,
                MaxSignatureLen,
                MaxSubmissionLen,
                MaxProofLen,
                MaxAdditionalParamsLen,
            >,
        >,
        crate::Error,
    >;

    /// Queries next job ID.
    ///
    ///  # Returns
    ///  Next job ID.
    async fn query_next_job_id(&self, at: [u8; 32]) -> Result<u64, crate::Error>;

    /// Queries restaker's role key
    ///
    ///  # Returns
    ///  Role key
    async fn query_restaker_role_key(
        &self,
        at: [u8; 32],
        address: AccountId32,
    ) -> Result<Option<Vec<u8>>, crate::Error>;

    /// Queries restaker's roles
    ///
    /// # Returns
    /// List of roles enabled for restaker
    async fn query_restaker_roles(
        &self,
        at: [u8; 32],
        address: AccountId32,
    ) -> Result<Vec<roles::RoleType>, crate::Error>;
}

impl<C: ClientWithApi> JobsClient<C> {
    pub async fn query_jobs_by_validator(
        &self,
        at: [u8; 32],
        validator: sr25519::Public,
    ) -> Result<
        Vec<
            jobs::RpcResponseJobsData<
                AccountId32,
                u64,
                MaxParticipants,
                MaxSubmissionLen,
                MaxAdditionalParamsLen,
            >,
        >,
        crate::Error,
    > {
        Ok(self
            .client
            .query_jobs_by_validator(at, AccountId32::from(validator.0))
            .await?
            .into_iter()
            .flatten()
            .collect())
    }

    pub async fn query_restaker_role_key(
        &self,
        at: [u8; 32],
        address: sr25519::Public,
    ) -> Result<Option<ecdsa::Public>, crate::Error> {
        self.client
            .query_restaker_role_key(at, AccountId32::from(address.0))
            .await
            .map(|r| r.and_then(|v| ecdsa::Public::from_slice(v.as_slice()).ok()))
    }

    pub async fn query_job_by_id(
        &self,
        at: [u8; 32],
        role_type: roles::RoleType,
        job_id: u64,
    ) -> Result<
        Option<
            jobs::RpcResponseJobsData<
                AccountId32,
                u64,
                MaxParticipants,
                MaxSubmissionLen,
                MaxAdditionalParamsLen,
            >,
        >,
        crate::Error,
    > {
        self.client.query_job_by_id(at, role_type, job_id).await
    }

    pub async fn query_job_result(
        &self,
        at: [u8; 32],
        role_type: roles::RoleType,
        job_id: u64,
    ) -> Result<
        Option<
            jobs::PhaseResult<
                AccountId32,
                u64,
                MaxParticipants,
                MaxKeyLen,
                MaxDataLen,
                MaxSignatureLen,
                MaxSubmissionLen,
                MaxProofLen,
                MaxAdditionalParamsLen,
            >,
        >,
        crate::Error,
    > {
        self.client.query_job_result(at, role_type, job_id).await
    }

    pub async fn submit_job_result(
        &self,
        role_type: roles::RoleType,
        job_id: u64,
        result: jobs::JobResult<
            MaxParticipants,
            MaxKeyLen,
            MaxSignatureLen,
            MaxDataLen,
            MaxProofLen,
            MaxAdditionalParamsLen,
        >,
    ) -> Result<(), crate::Error> {
        self.pallet_tx
            .submit_job_result(role_type, job_id, result)
            .await
    }
}

impl<MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen> JobTypeExt
    for jobs::JobType<AccountId32, MaxParticipants, MaxSubmissionLen, MaxAdditionalParamsLen>
{
    fn is_phase_one(&self) -> bool {
        use jobs::JobType::*;
        matches!(self, DKGTSSPhaseOne(_) | ZkSaaSPhaseOne(_))
    }

    fn get_participants(self) -> Option<Vec<AccountId32>> {
        use jobs::JobType::*;
        match self {
            DKGTSSPhaseOne(p) => Some(p.participants.0),
            ZkSaaSPhaseOne(p) => Some(p.participants.0),
            _ => None,
        }
    }

    fn get_threshold(self) -> Option<u8> {
        use jobs::JobType::*;
        match self {
            DKGTSSPhaseOne(p) => Some(p.threshold),
            _ => None,
        }
    }

    fn get_role_type(&self) -> roles::RoleType {
        match self {
            DKGTSSPhaseOne(job) => RoleType::Tss(job.role_type.clone()),
            ZkSaaSPhaseOne(job) => RoleType::ZkSaaS(job.role_type.clone()),
            DKGTSSPhaseTwo(job) => RoleType::Tss(job.role_type.clone()),
            ZkSaaSPhaseTwo(job) => RoleType::ZkSaaS(job.role_type.clone()),
            DKGTSSPhaseThree(job) => RoleType::Tss(job.role_type.clone()),
            DKGTSSPhaseFour(job) => RoleType::Tss(job.role_type.clone()),
        }
    }

    fn get_phase_one_id(&self) -> Option<u64> {
        use jobs::JobType::*;
        match self {
            DKGTSSPhaseTwo(info) => Some(info.phase_one_id),
            DKGTSSPhaseThree(info) => Some(info.phase_one_id),
            DKGTSSPhaseFour(info) => Some(info.phase_one_id),
            ZkSaaSPhaseTwo(info) => Some(info.phase_one_id),
            _ => None,
        }
    }

    fn get_permitted_caller(self) -> Option<AccountId32> {
        use jobs::JobType::*;
        match self {
            DKGTSSPhaseOne(p) => p.permitted_caller,
            ZkSaaSPhaseOne(p) => p.permitted_caller,
            _ => None,
        }
    }
}

impl<
        JobId,
        MaxParticipants,
        MaxKeyLen,
        MaxDataLen,
        MaxSignatureLen,
        MaxSubmissionLen,
        MaxProofLen,
        MaxAdditionalParamsLen,
    > PhaseResultExt
    for jobs::PhaseResult<
        AccountId32,
        JobId,
        MaxParticipants,
        MaxKeyLen,
        MaxDataLen,
        MaxSignatureLen,
        MaxSubmissionLen,
        MaxProofLen,
        MaxAdditionalParamsLen,
    >
{
    fn participants(&self) -> Option<Vec<AccountId32>> {
        match &self.job_type {
            jobs::JobType::DKGTSSPhaseOne(p) => Some(p.participants.0.clone()),
            jobs::JobType::ZkSaaSPhaseOne(p) => Some(p.participants.0.clone()),
            _ => None,
        }
    }
    fn threshold(&self) -> Option<u8> {
        match &self.job_type {
            jobs::JobType::DKGTSSPhaseOne(p) => Some(p.threshold),
            _ => None,
        }
    }
}

#[async_trait]
impl<C: Client> Client for JobsClient<C> {
    async fn get_next_finality_notification(&self) -> Option<FinalityNotification> {
        self.client.get_next_finality_notification().await
    }

    async fn get_latest_finality_notification(&self) -> Option<FinalityNotification> {
        self.client.get_latest_finality_notification().await
    }
}
/// A [`Signer`] implementation that can be constructed from an [`sp_core::Pair`].
#[derive(Clone)]
pub struct PairSigner<T: subxt::Config> {
    account_id: T::AccountId,
    signer: sp_core::sr25519::Pair,
}

impl<T: subxt::Config> PairSigner<T>
where
    T::AccountId: From<[u8; 32]>,
{
    pub fn new(signer: sp_core::sr25519::Pair) -> Self {
        let account_id = T::AccountId::from(signer.public().into());
        Self { account_id, signer }
    }
}

impl<T: subxt::Config> subxt::tx::Signer<T> for PairSigner<T>
where
    T::Signature: From<subxt::utils::MultiSignature>,
{
    fn account_id(&self) -> T::AccountId {
        self.account_id.clone()
    }

    fn address(&self) -> T::Address {
        self.account_id.clone().into()
    }

    fn sign(&self, signer_payload: &[u8]) -> T::Signature {
        subxt::utils::MultiSignature::Sr25519(self.signer.sign(signer_payload).0).into()
    }
}

#[async_trait]
#[auto_impl(Arc)]
pub trait PalletSubmitter: Send + Sync + 'static {
    async fn submit_job_result(
        &self,
        role_type: roles::RoleType,
        job_id: u64,

        result: jobs::JobResult<
            MaxParticipants,
            MaxKeyLen,
            MaxSignatureLen,
            MaxDataLen,
            MaxProofLen,
            MaxAdditionalParamsLen,
        >,
    ) -> Result<(), crate::Error>;
}

pub struct SubxtPalletSubmitter<C, S>
where
    C: subxt::Config,
    S: subxt::tx::Signer<C>,
{
    subxt_client: OnlineClient<C>,
    signer: S,
    logger: DebugLogger,
}

#[async_trait]
impl<C, S> PalletSubmitter for SubxtPalletSubmitter<C, S>
where
    C: subxt::Config + Send + Sync + 'static,
    S: subxt::tx::Signer<C> + Send + Sync + 'static,
    C::AccountId: std::fmt::Display + Send + Sync + 'static,
    C::Hash: std::fmt::Display,
    <C::ExtrinsicParams as subxt::config::ExtrinsicParams<C>>::OtherParams:
        Default + Send + Sync + 'static,
{
    async fn submit_job_result(
        &self,
        role_type: roles::RoleType,
        job_id: u64,
        result: jobs::JobResult<
            MaxParticipants,
            MaxKeyLen,
            MaxSignatureLen,
            MaxDataLen,
            MaxProofLen,
            MaxAdditionalParamsLen,
        >,
    ) -> Result<(), crate::Error> {
        let tx = api::tx()
            .jobs()
            .submit_job_result(role_type, job_id, result);
        match self.submit(&tx).await {
            Ok(hash) => {
                self.logger.info(format!(
                    "({}) Job result submitted for job_id: {job_id} at block: {hash}",
                    self.signer.account_id(),
                ));
                Ok(())
            }
            Err(err) if err.to_string().contains("JobNotFound") => {
                self.logger.warn(format!(
                    "({}) Job not found for job_id: {job_id}",
                    self.signer.account_id(),
                ));
                Ok(())
            }
            Err(err) => {
                return Err(crate::Error::ClientError {
                    err: format!("Failed to submit job result: {err:?}"),
                })
            }
        }
    }
}

impl<C, S> SubxtPalletSubmitter<C, S>
where
    C: subxt::Config,
    C::AccountId: std::fmt::Display,
    S: subxt::tx::Signer<C>,
    C::Hash: std::fmt::Display,
    <C::ExtrinsicParams as subxt::config::ExtrinsicParams<C>>::OtherParams: Default,
{
    pub async fn new(signer: S, logger: DebugLogger) -> Result<Self, crate::Error> {
        let subxt_client =
            OnlineClient::<C>::new()
                .await
                .map_err(|err| crate::Error::ClientError {
                    err: format!("Failed to setup api: {err:?}"),
                })?;
        Ok(Self::with_client(subxt_client, signer, logger))
    }

    pub fn with_client(subxt_client: OnlineClient<C>, signer: S, logger: DebugLogger) -> Self {
        Self {
            subxt_client,
            signer,
            logger,
        }
    }

    async fn submit<Call: TxPayload>(&self, call: &Call) -> anyhow::Result<C::Hash> {
        if let Some(details) = call.validation_details() {
            self.logger.trace(format!(
                "({}) Submitting {}.{}",
                self.signer.account_id(),
                details.pallet_name,
                details.call_name
            ));
        }
        Ok(self
            .subxt_client
            .tx()
            .sign_and_submit_then_watch_default(call, &self.signer)
            .await?
            .wait_for_finalized_success()
            .await?
            .block_hash())
    }
}

#[cfg(test)]
mod tests {

    use tangle_subxt::{
        subxt::{tx::Signer, utils::AccountId32, PolkadotConfig},
        tangle_testnet_runtime::api,
        tangle_testnet_runtime::api::runtime_types::{
            bounded_collections::bounded_vec::BoundedVec,
            tangle_primitives::{jobs, roles},
        },
    };

    use super::*;

    #[tokio::test]
    #[ignore = "This test requires a running substrate node"]
    async fn subxt_pallet_submitter() -> anyhow::Result<()> {
        let logger = DebugLogger {
            peer_id: "test".into(),
        };
        let alice = subxt_signer::sr25519::dev::alice();
        let bob = subxt_signer::sr25519::dev::bob();
        let alice_account_id =
            <subxt_signer::sr25519::Keypair as Signer<PolkadotConfig>>::account_id(&alice);
        let bob_account_id =
            <subxt_signer::sr25519::Keypair as Signer<PolkadotConfig>>::account_id(&bob);
        let pallet_tx =
            SubxtPalletSubmitter::<PolkadotConfig, _>::new(alice.clone(), logger).await?;
        let dkg_phase_one = jobs::JobSubmission {
            expiry: 100u64,
            ttl: 100u64,
            fallback: jobs::FallbackOptions::Destroy,
            job_type: jobs::JobType::DKGTSSPhaseOne(jobs::tss::DKGTSSPhaseOneJobType {
                participants: BoundedVec::<AccountId32>(vec![alice_account_id, bob_account_id]),
                threshold: 1u8,
                permitted_caller: None,
                role_type: roles::tss::ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1,
                __subxt_unused_type_params: Default::default(),
            }),
        };
        let tx = api::tx().jobs().submit_job(dkg_phase_one);
        let _hash = pallet_tx.submit(&tx).await?;
        Ok(())
    }
}
