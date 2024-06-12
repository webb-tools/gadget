use aws_sdk_kms::Client;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
struct Asn1EcPublicKey {
    algorithm: String,
    parameters: String,
    public_key: Vec<u8>,
}

pub async fn get_ecdsa_public_key(
    client: &Client,
    key_id: &str,
) -> Result<PublicKey, Box<dyn Error>> {
    let get_pub_key_output = client.get_public_key().key_id(key_id).send().await?;

    let public_key_der = get_pub_key_output.public_key.unwrap();

    let public_key_der = &public_key_der.into_inner()[..];

    // Parse ASN.1 DER encoded public key
    let pk_info = picky_asn1_der::from_bytes::<Asn1EcPublicKey>(public_key_der)?;

    // Extract public key bytes
    let public_key_bytes = pk_info.public_key;

    // Parse the public key bytes to create an ECDSA public key
    let public_key = PublicKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|_| "Failed to parse ECDSA public key")?;

    Ok(public_key)
}
