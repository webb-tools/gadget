use crate::protocol::keygen::BlsKeygenAdditionalParams;
use async_trait::async_trait;
use gadget_common::full_protocol::SharedOptional;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use gadget_common::{generate_protocol, generate_setup_and_run_command};
use protocol::signing::BlsSigningAdditionalParams;
use protocol_macros::protocol;

pub mod constants;
pub mod protocol;

generate_protocol!(
    "BLS-Keygen-Protocol",
    BlsKeygenProtocol,
    BlsKeygenAdditionalParams,
    protocol::keygen::generate_protocol_from,
    protocol::keygen::create_next_job,
    jobs::JobType::DKGTSSPhaseOne(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::GennaroDKGBls381)
);
generate_protocol!(
    "BLS-Signing-Protocol",
    BlsSigningProtocol,
    BlsSigningAdditionalParams,
    protocol::signing::generate_protocol_from,
    protocol::signing::create_next_job,
    jobs::JobType::DKGTSSPhaseTwo(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::GennaroDKGBls381)
);
generate_setup_and_run_command!(BlsKeygenProtocol, BlsSigningProtocol);

#[cfg(test)]
test_utils::generate_signing_and_keygen_tss_tests!(
    2,
    3,
    2,
    ThresholdSignatureRoleType::GennaroDKGBls381
);
