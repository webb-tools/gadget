use crate::protocol::keygen::SilentShardDKLS23KeygenExtraParams;
use crate::protocol::sign::SilentShardDKLS23SigningExtraParams;
use async_trait::async_trait;
use gadget_common::full_protocol::SharedOptional;
use gadget_common::prelude::*;
use gadget_common::tangle_runtime::*;
use gadget_common::{generate_protocol, generate_setup_and_run_command};
use protocol_macros::protocol;

pub mod constants;
pub mod protocol;
pub mod rounds;

generate_protocol!(
    "Silent-Shared-DKLS23-Keygen-Protocol",
    SilentShardDKLS23KeygenProtocol,
    SilentShardDKLS23KeygenExtraParams,
    crate::protocol::keygen::generate_protocol_from,
    crate::protocol::keygen::create_next_job,
    jobs::JobType::DKGTSSPhaseOne(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::SilentShardDKLS23Secp256k1)
);
generate_protocol!(
    "Silent-Shared-DKLS23-Signing-Protocol",
    SilentShardDKLS23SigningProtocol,
    SilentShardDKLS23SigningExtraParams,
    crate::protocol::sign::generate_protocol_from,
    crate::protocol::sign::create_next_job,
    jobs::JobType::DKGTSSPhaseTwo(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::SilentShardDKLS23Secp256k1)
);

generate_setup_and_run_command!(
    SilentShardDKLS23KeygenProtocol,
    SilentShardDKLS23SigningProtocol
);

#[cfg(test)]
mod secp256k1 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        tangle_primitives::roles::ThresholdSignatureRoleType::SilentShardDKLS23Secp256k1
    );
}
