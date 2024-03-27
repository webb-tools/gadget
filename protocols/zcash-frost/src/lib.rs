use crate::protocol::keygen::ZcashFrostKeygenExtraParams;
use crate::protocol::sign::ZcashFrostSigningExtraParams;
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
    "Zcash-FROST-Keygen-Protocol",
    ZcashFrostKeygenProtocol,
    ZcashFrostKeygenExtraParams,
    crate::protocol::keygen::generate_protocol_from,
    crate::protocol::keygen::create_next_job,
    jobs::JobType::DKGTSSPhaseOne(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostP256)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostP384)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255)
);
generate_protocol!(
    "Zcash-FROST-Signing-Protocol",
    ZcashFrostSigningProtocol,
    ZcashFrostSigningExtraParams,
    crate::protocol::sign::generate_protocol_from,
    crate::protocol::sign::create_next_job,
    jobs::JobType::DKGTSSPhaseTwo(_),
    roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostEd25519)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostEd448)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostP256)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostP384)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostSecp256k1)
        | roles::RoleType::Tss(roles::tss::ThresholdSignatureRoleType::ZcashFrostRistretto255)
);

generate_setup_and_run_command!(ZcashFrostKeygenProtocol, ZcashFrostSigningProtocol);

#[cfg(test)]
mod secp256k1 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostSecp256k1
    );
}

#[cfg(test)]
mod ristretto255 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostRistretto255
    );
}

#[cfg(test)]
mod p256 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostP256
    );
}

#[cfg(test)]
mod p384 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostP384
    );
}

#[cfg(test)]
mod ed25519 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostEd25519
    );
}

#[cfg(test)]
mod ed448 {
    test_utils::generate_signing_and_keygen_tss_tests!(
        2,
        3,
        2,
        ThresholdSignatureRoleType::ZcashFrostEd448
    );
}
