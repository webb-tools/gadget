use tangle_primitives::jobs::{
    DKGTSSPhaseOneJobType, DKGTSSPhaseTwoJobType, JobId, JobSubmission, JobType,
};
use tangle_primitives::roles::{RoleType, ThresholdSignatureRoleType};
use tangle_primitives::AccountId;
use test_utils::mock::{id_to_sr25519_public, Jobs, RuntimeOrigin};
use test_utils::sync::substrate_test_channel::MultiThreadedTestExternalities;

const N: usize = 3;
const T: usize = 2;

#[tokio::test(flavor = "multi_thread")]
async fn signing_with_derivation() {
    test_utils::setup_log();

    let ext = new_test_ext::<N>().await;
    let threshold_sig_ty = ThresholdSignatureRoleType::DfnsCGGMP21Secp256k1;
    let keygen_job_id = wait_for_keygen::<N, T>(&ext, threshold_sig_ty).await;
    assert_eq!(
        wait_for_signing::<N>(&ext, keygen_job_id, threshold_sig_ty).await,
        1
    );
}

async fn wait_for_keygen<const N: usize, const T: usize>(
    ext: &MultiThreadedTestExternalities,
    threshold_sig_ty: ThresholdSignatureRoleType,
) -> JobId {
    let job_id = ext
        .execute_with_async(move || {
            let job_id = Jobs::next_job_id();
            let identities = (0..N)
                .map(|i| id_to_sr25519_public(i as u8))
                .map(AccountId::from)
                .collect::<Vec<_>>();

            let submission = JobSubmission {
                fallback: tangle_primitives::jobs::FallbackOptions::Destroy,
                expiry: 100,
                ttl: 100,
                job_type: JobType::DKGTSSPhaseOne(DKGTSSPhaseOneJobType {
                    participants: identities.clone().try_into().unwrap(),
                    threshold: T as _,
                    permitted_caller: None,
                    role_type: threshold_sig_ty,
                }),
            };

            assert!(
                Jobs::submit_job(RuntimeOrigin::signed(identities[0].clone()), submission).is_ok()
            );

            log::info!(target: "gadget", "******* Submitted Keygen Job {job_id}");
            job_id
        })
        .await;

    test_utils::wait_for_job_completion(ext, RoleType::Tss(threshold_sig_ty), job_id).await;
    job_id
}

async fn wait_for_signing<const N: usize>(
    ext: &MultiThreadedTestExternalities,
    keygen_job_id: JobId,
    threshold_sig_ty: ThresholdSignatureRoleType,
) -> JobId {
    let job_id = ext
        .execute_with_async(move || {
            let job_id = Jobs::next_job_id();
            let identities = (0..N)
                .map(|i| id_to_sr25519_public(i as u8))
                .map(AccountId::from)
                .collect::<Vec<_>>();
            let submission = JobSubmission {
                fallback: tangle_primitives::jobs::FallbackOptions::Destroy,
                expiry: 100,
                ttl: 100,
                job_type: JobType::DKGTSSPhaseTwo(DKGTSSPhaseTwoJobType {
                    phase_one_id: keygen_job_id,
                    derivation_path: Some(
                        String::from("m/44'/60'/0'/0/0")
                            .as_bytes()
                            .to_vec()
                            .try_into()
                            .unwrap(),
                    ),
                    submission: Vec::from("Hello, world!").try_into().unwrap(),
                    role_type: threshold_sig_ty,
                }),
            };

            assert!(
                Jobs::submit_job(RuntimeOrigin::signed(identities[0].clone()), submission).is_ok()
            );

            log::info!(target: "gadget", "******* Submitted Signing Job {job_id}");
            job_id
        })
        .await;

    test_utils::wait_for_job_completion(ext, RoleType::Tss(threshold_sig_ty), job_id).await;
    job_id
}

async fn new_test_ext<const N: usize>() -> MultiThreadedTestExternalities {
    test_utils::mock::new_test_ext::<N, 4, (), _, _>((), dfns_cggmp21_protocol::setup_node).await
}
