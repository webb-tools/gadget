use crate::protocols::signing::WstsSigningExtraParams;
use gadget_common::generate_protocol;
use gadget_common::prelude::*;
use protocols::keygen::WstsKeygenExtraParams;

pub mod protocols;

generate_protocol!(
    "WSTS-Keygen-Protocol",
    WstsKeygenProtocol,
    WstsKeygenExtraParams,
    protocols::keygen::generate_protocol_from,
    protocols::keygen::create_next_job,
    jobs::JobType::DKGTSSPhaseOne(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::WstsV2)
);

generate_protocol!(
    "WSTS-Signing-Protocol",
    WstsSigningProtocol,
    WstsSigningExtraParams,
    protocols::signing::generate_protocol_from,
    protocols::signing::create_next_job,
    jobs::JobType::DKGTSSPhaseTwo(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::WstsV2)
);

generate_setup_and_run_command!(WstsKeygenProtocol, WstsSigningProtocol);

#[cfg(test)]
mod wsts {
    test_utils::generate_signing_and_keygen_tss_tests!(2, 3, 4, ThresholdSignatureRoleType::WstsV2);
}
