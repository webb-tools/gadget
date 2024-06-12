use alloy_consensus::{SignableTransaction, TypedTransaction};
use alloy_primitives::{keccak256, Address, Signature, U256};
use ark_ff::MontConfig;

use k256::{ecdsa, elliptic_curve::generic_array::GenericArray};
use std::{future::Future, pin::Pin, sync::Arc};
use thiserror::Error;

use super::get_signature::get_ecdsa_signature;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Chain ID is required")]
    ChainIdRequired,
    #[error("KMS client is required")]
    KmsClientRequired,
    #[error("Public key is required")]
    PublicKeyRequired,
    #[error("Failed to get ECDSA signature: {0}")]
    GetSignatureError(String),
    #[error("Failed to verify signature")]
    VerifySignatureError,
    #[error("Not authorized")]
    NotAuthorized,
}

pub type SignerFn = Arc<
    dyn Fn(
            Address,
            TypedTransaction,
        ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>>>>
        + Send
        + Sync,
>;

/// Create a new KMS signer
/// `new_kms_signer` is a function that creates a new KMS signer.
/// It takes four parameters:
/// - `svc`: a client for the AWS KMS service
/// - `public_key`: a 64-byte public key for the ECDSA (Elliptic Curve Digital Signature Algorithm)
/// - `key_id`: a unique identifier for the key in the AWS KMS
/// - `chain_id`: an identifier for the blockchain network
///
/// The function returns a `SignerFn` which is a function that takes an `Address` and a `SignableTransaction` and returns a `Result`
/// with a `Signed<SignableTransaction>` if successful, or a `SignerError` if an error occurs.
pub fn new_kms_signer(
    svc: super::Client,
    public_key: ecdsa::VerifyingKey,
    key_id: String,
    chain_id: U256,
) -> Result<SignerFn, SignerError> {
    if chain_id == U256::ZERO {
        return Err(SignerError::ChainIdRequired);
    }

    let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
    let key_addr = Address::from_slice(&keccak256(&public_key_bytes[1..])[12..]);

    Ok(Arc::new(move |address, tx| {
        let svc_clone = svc.clone();
        let key_id_clone = key_id.clone();

        Box::pin(async move {
            if address != key_addr {
                return Err(SignerError::NotAuthorized);
            }

            let mut buf = Vec::new();
            match tx {
                TypedTransaction::Legacy(txx) => txx.encode_for_signing(&mut buf),
                TypedTransaction::Eip2930(txx) => txx.encode_for_signing(&mut buf),
                TypedTransaction::Eip1559(txx) => txx.encode_for_signing(&mut buf),
                TypedTransaction::Eip4844(txx) => txx.encode_for_signing(&mut buf),
            };

            let tx_hash = keccak256(&buf[..]);

            let (r, s) = get_ecdsa_signature(&svc_clone, &key_id_clone, &tx_hash[..])
                .await
                .map_err(|e| SignerError::GetSignatureError(e.to_string()))?;

            let s_bigint = U256::from_be_bytes::<32>(s.clone().try_into().unwrap());
            let secp_order =
                U256::from_limbs(<ark_secp256k1::FrConfig as MontConfig<4>>::MODULUS.0);
            let s_adjusted = if s_bigint > secp_order.div_ceil(U256::from(2)) {
                (secp_order - s_bigint).to_be_bytes::<32>().to_vec()
            } else {
                s
            };

            let signature = ecdsa::Signature::from_scalars(
                *GenericArray::from_slice(&r[..]),
                *GenericArray::from_slice(&s_adjusted[..]),
            )
            .map_err(|_| SignerError::VerifySignatureError)?;

            let sig_result =
                Signature::from_bytes_and_parity(&signature.to_bytes().to_vec()[..], 0);
            let sig = if sig_result.is_err() {
                Signature::from_bytes_and_parity(&signature.to_bytes().to_vec()[..], 1)
                    .map_err(|_| SignerError::VerifySignatureError)?
            } else {
                sig_result.unwrap()
            };

            Ok(sig)
        })
    }))
}
