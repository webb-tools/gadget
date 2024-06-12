use aws_sdk_kms::{
    types::{MessageType, SigningAlgorithmSpec},
    Client, Error,
};
use aws_sdk_s3::primitives::Blob;
use picky_asn1_der::Asn1RawDer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct Asn1EcSig {
    r: Asn1RawDer,
    s: Asn1RawDer,
}

pub async fn get_ecdsa_signature(
    client: &Client,
    key_id: &str,
    msg: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let sign_output = client
        .sign()
        .key_id(key_id)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .message_type(MessageType::Digest)
        .message(Blob::new(msg))
        .send()
        .await?;

    let signature = sign_output.signature.unwrap().into_inner();

    let asn1_sig: Asn1EcSig = picky_asn1_der::from_bytes(&signature[..])
        .expect("Failed to parse ASN.1 DER encoded signature");

    Ok((asn1_sig.r.0, asn1_sig.s.0))
}
