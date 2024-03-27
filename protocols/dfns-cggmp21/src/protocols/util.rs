use dfns_cggmp21::generic_ec::coords::HasAffineX;
use dfns_cggmp21::generic_ec::{Point, Scalar};
use dfns_cggmp21::signing::Signature;
use dfns_cggmp21::supported_curves::{Secp256k1, Secp256r1, Stark};
use gadget_common::gadget::message::UserID;
use gadget_core::job::JobError;
use rand::prelude::SliceRandom;
use signature::hazmat::PrehashVerifier;
use sp_core::ecdsa;
use sp_core::ecdsa::Public;
use std::collections::HashMap;

pub type ChosenSigners = (u16, Vec<u16>, HashMap<UserID, Public>);

/// Given a list of participants, choose `t` of them and return the index of the current participant
/// and the indices of the chosen participants, as well as a mapping from the index to the account
/// id.
///
/// # Errors
/// If we are not selected to sign the message it will return an error
/// [`gadget_common::Error::ParticipantNotSelected`].
///
/// # Panics
/// If the current participant is not in the list of participants it will panic.
pub fn choose_signers<R: rand::Rng>(
    rng: &mut R,
    my_role_key: &ecdsa::Public,
    participants: &[ecdsa::Public],
    t: u16,
) -> Result<ChosenSigners, gadget_common::Error> {
    let selected_participants = participants
        .choose_multiple(rng, t as usize)
        .cloned()
        .collect::<Vec<_>>();

    let selected_participants_indices = selected_participants
        .iter()
        .map(|p| participants.iter().position(|x| x == p).unwrap() as u16)
        .collect::<Vec<_>>();

    let j = participants
        .iter()
        .position(|p| p == my_role_key)
        .expect("Should exist") as u16;

    let i = selected_participants_indices
        .iter()
        .position(|p| p == &j)
        .map(|i| i as u16)
        .ok_or_else(|| gadget_common::Error::ParticipantNotSelected {
            id: *my_role_key,
            reason: String::from("we are not selected to sign"),
        })?;

    let user_id_to_account_id_mapping = selected_participants
        .clone()
        .into_iter()
        .enumerate()
        .map(|(i, p)| (i as UserID, p))
        .collect();
    Ok((
        i,
        selected_participants_indices,
        user_id_to_account_id_mapping,
    ))
}

pub trait SignatureVerifier {
    fn verify_signature(
        signature_bytes: [u8; 64],
        data_hash: &[u8; 32],
        public_key_bytes: &[u8],
    ) -> Result<(), JobError>;
}

impl SignatureVerifier for Secp256k1 {
    fn verify_signature(
        signature_bytes: [u8; 64],
        data_hash: &[u8; 32],
        public_key_bytes: &[u8],
    ) -> Result<(), JobError> {
        let public_key =
            secp256k1::PublicKey::from_slice(public_key_bytes).map_err(|e| JobError {
                reason: format!("Failed to convert public key to secp256k1: {:?}", e),
            })?;
        let message = secp256k1::Message::from_digest_slice(data_hash).map_err(|e| JobError {
            reason: format!("Failed to convert data hash to secp256k1: {:?}", e),
        })?;
        let signature =
            secp256k1::ecdsa::Signature::from_compact(&signature_bytes).map_err(|e| JobError {
                reason: format!("Failed to convert signature to compact: {:?}", e),
            })?;
        signature
            .verify(&message, &public_key)
            .map_err(|e| JobError {
                reason: format!("Failed to verify signature: {:?}", e),
            })?;

        Ok(())
    }
}

impl SignatureVerifier for Secp256r1 {
    fn verify_signature(
        signature_bytes: [u8; 64],
        data_hash: &[u8; 32],
        public_key_bytes: &[u8],
    ) -> Result<(), JobError> {
        use p256::elliptic_curve::group::GroupEncoding;

        let affine_point = p256::AffinePoint::from_bytes(public_key_bytes.into())
            .expect("Failed to convert public key to affine point");
        let verifying_key =
            p256::ecdsa::VerifyingKey::from_affine(affine_point).map_err(|_| JobError {
                reason: "Failed to convert public key to verifying key".to_string(),
            })?;
        let signature =
            p256::ecdsa::Signature::from_slice(&signature_bytes).map_err(|_| JobError {
                reason: "Failed to convert signature".to_string(),
            })?;

        verifying_key
            .verify_prehash(data_hash, &signature)
            .map(|_| signature_bytes)
            .map_err(|e| JobError {
                reason: format!("Failed to verify signature: {:?}", e),
            })?;

        Ok(())
    }
}

impl SignatureVerifier for Stark {
    fn verify_signature(
        signature_bytes: [u8; 64],
        data_hash: &[u8; 32],
        public_key_bytes: &[u8],
    ) -> Result<(), JobError> {
        if public_key_bytes.is_empty() {
            return Err(JobError {
                reason: "Public key is empty".to_string(),
            });
        }
        let signature =
            Signature::<Stark>::read_from_slice(&signature_bytes).ok_or_else(|| JobError {
                reason: "Failed to construct signature from bytes".to_string(),
            })?;

        let public_key_x: Scalar<Stark> = Point::from_bytes(public_key_bytes)
            .map_err(|_| JobError {
                reason: "Failed to convert public key to point".to_string(),
            })?
            .x()
            .ok_or(JobError {
                reason: "Failed to convert public key to point".to_string(),
            })?
            .to_scalar();

        let public_key = convert_stark_scalar(&public_key_x)?;
        let message = convert_stark_scalar(&Scalar::<Stark>::from_be_bytes_mod_order(data_hash))?;
        let r = convert_stark_scalar(&signature.r)?;
        let s = convert_stark_scalar(&signature.s)?;

        let success =
            starknet_crypto::verify(&public_key, &message, &r, &s).map_err(|_| JobError {
                reason: "Failed to verify signature".to_string(),
            })?;

        if success {
            Ok(())
        } else {
            Err(JobError {
                reason: "Failed to verify signature".to_string(),
            })
        }
    }
}

pub fn convert_stark_scalar(x: &Scalar<Stark>) -> Result<starknet_crypto::FieldElement, JobError> {
    let bytes = x.to_be_bytes();
    debug_assert_eq!(bytes.len(), 32);
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(bytes.as_bytes());
    starknet_crypto::FieldElement::from_bytes_be(&buffer).map_err(|e| JobError {
        reason: format!("Failed to convert scalar: {:?}", e),
    })
}
