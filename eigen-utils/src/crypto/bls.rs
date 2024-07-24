use alloy_primitives::U256;
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, QuadExtField, Zero};
use ark_ff::{BigInteger256, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::One;
use ark_std::UniformRand;
use base64::prelude::*;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use hex::FromHex;
use rand::thread_rng;
use scrypt::password_hash::{PasswordHashString, SaltString};
use scrypt::{password_hash, Params, Scrypt};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::fs;
use std::ops::{Div, Mul, Neg};
use std::path::Path;

use crate::types::AvsError;

use super::bn254::{map_to_curve, mul_by_generator_g1};
use super::pairing_products::{InnerProduct, PairingInnerProduct};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedBLSKeyJSONV3 {
    pub pub_key: G1Point,
    pub crypto: serde_json::Value, // Adjust this type to match your specific encryption structure
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct G1Point {
    pub x: U256,
    pub y: U256,
}

impl CanonicalSerialize for G1Point {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let affine = g1_point_to_ark_point(self);
        affine.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let affine = g1_point_to_ark_point(self);
        affine.serialized_size(compress)
    }
}

impl Valid for G1Point {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        let affine = g1_point_to_ark_point(self);
        affine.check()
    }
}

impl CanonicalDeserialize for G1Point {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let affine = G1Affine::deserialize_with_mode(reader, compress, validate)?;
        Ok(ark_point_to_g1_point(&affine))
    }
}

impl G1Point {
    pub fn new(x: Fq, y: Fq) -> Self {
        // let point = G1Projective::new(x, y, Fq::one());
        let x = U256::from_limbs(x.0 .0);
        let y = U256::from_limbs(y.0 .0);
        G1Point { x, y }
    }

    pub fn zero() -> Self {
        Self::new(Fq::zero(), Fq::zero())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ser_buf = vec![0; self.serialized_size(ark_serialize::Compress::Yes)];
        let _ = self.serialize_compressed(&mut ser_buf);
        ser_buf
    }

    pub fn neg(&self) -> Self {
        let affine = g1_point_to_ark_point(self);
        let neg_affine = affine.neg();
        ark_point_to_g1_point(&neg_affine)
    }

    pub fn generator() -> Self {
        let gen = G1Affine::generator();
        ark_point_to_g1_point(&gen)
    }

    pub fn add(&mut self, other: &G1Point) {
        let affine_p1 = g1_point_to_ark_point(self);
        let affine_p2 = g1_point_to_ark_point(other);

        let pt = (affine_p1 + affine_p2).into_affine();
        *self = ark_point_to_g1_point(&pt);
    }

    pub fn sub(&mut self, other: &G1Point) {
        let affine_p1 = g1_point_to_ark_point(self);
        let affine_p2 = g1_point_to_ark_point(other);

        let pt = (affine_p1 - affine_p2).into_affine();
        *self = ark_point_to_g1_point(&pt);
    }

    pub fn mul(&mut self, scalar: Fr) {
        let affine = g1_point_to_ark_point(self);

        let pt = affine.mul_bigint(scalar.0).into_affine();
        *self = ark_point_to_g1_point(&pt);
    }

    pub fn from_ark_g1(ark_g1: &G1Affine) -> Self {
        ark_point_to_g1_point(ark_g1)
    }

    pub fn to_ark_g1(&self) -> G1Affine {
        println!("TO ARK G1");
        g1_point_to_ark_point(self)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct G2Point {
    pub x: [U256; 2],
    pub y: [U256; 2],
}

impl CanonicalSerialize for G2Point {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let affine = g2_point_to_ark_point(self);
        affine.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let affine = g2_point_to_ark_point(self);
        affine.serialized_size(compress)
    }
}

impl Valid for G2Point {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        let affine = g2_point_to_ark_point(self);
        affine.check()
    }
}

impl CanonicalDeserialize for G2Point {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let affine = G2Affine::deserialize_with_mode(reader, compress, validate)?;
        Ok(ark_point_to_g2_point(&affine))
    }
}

impl G2Point {
    pub fn new(x: [Fr; 2], y: [Fr; 2]) -> Self {
        Self {
            x: [U256::from_limbs(x[0].0 .0), U256::from_limbs(x[1].0 .0)],
            y: [U256::from_limbs(y[0].0 .0), U256::from_limbs(y[1].0 .0)],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ser_buf = vec![0; self.serialized_size(ark_serialize::Compress::Yes)];
        let _ = self.serialize_compressed(&mut ser_buf);
        ser_buf
    }

    pub fn neg(&self) -> Self {
        let affine = g2_point_to_ark_point(self);
        let neg_affine = -affine;
        ark_point_to_g2_point(&neg_affine)
    }

    pub fn zero() -> Self {
        Self::new([Fr::zero(), Fr::zero()], [Fr::zero(), Fr::zero()])
    }

    pub fn generator() -> Self {
        let gen = G2Affine::generator();
        ark_point_to_g2_point(&gen)
    }

    pub fn add(&mut self, other: &G2Point) {
        let affine_p1 = g2_point_to_ark_point(self);
        let affine_p2 = g2_point_to_ark_point(other);

        let pt = (affine_p1 + affine_p2).into_affine();
        *self = ark_point_to_g2_point(&pt);
    }

    pub fn sub(&mut self, other: &G2Point) {
        let affine_p1 = g2_point_to_ark_point(self);
        let affine_p2 = g2_point_to_ark_point(other);

        let pt = (affine_p1 - affine_p2).into_affine();
        *self = ark_point_to_g2_point(&pt);
    }

    pub fn mul(&mut self, scalar: Fq) {
        let affine = g2_point_to_ark_point(self);

        let pt = affine.mul_bigint(scalar.0).into_affine();
        *self = ark_point_to_g2_point(&pt);
    }

    pub fn from_ark_g2(ark_g2: &G2Affine) -> Self {
        ark_point_to_g2_point(ark_g2)
    }

    pub fn to_ark_g2(&self) -> G2Affine {
        g2_point_to_ark_point(self)
    }
}

pub fn g1_point_to_ark_point(pt: &G1Point) -> G1Affine {
    let one = Fq::new(BigInt(pt.x.as_limbs().clone()));
    println!("One: {:?}", one);
    let two = Fq::new(BigInt(pt.y.as_limbs().clone()));
    println!("Two: {:?}", two);
    G1Affine::new(one, two)
}

pub fn g1_point_to_g1_projective(pt: &G1Point) -> G1Projective {
    let one = Fq::new(BigInt(pt.x.as_limbs().clone()));
    let two = Fq::new(BigInt(pt.y.as_limbs().clone()));
    println!("LAST CHECKPOINT");
    G1Projective::new(one, two, Fq::one())
}

pub fn ark_point_to_g1_point(pt: &G1Affine) -> G1Point {
    G1Point::new(pt.x, pt.y)
    // G1Point {
    //     x: U256::from_limbs(pt.x.0 .0),
    //     y: U256::from_limbs(pt.y.0 .0),
    // }
}

pub fn g2_point_to_ark_point(pt: &G2Point) -> G2Affine {
    G2Affine::new(
        QuadExtField {
            c0: Fq::from(BigInt(pt.x[0].into_limbs())),
            c1: Fq::from(BigInt(pt.x[1].into_limbs())),
        },
        QuadExtField {
            c0: Fq::from(BigInt(pt.y[0].into_limbs())),
            c1: Fq::from(BigInt(pt.y[1].into_limbs())),
        },
    )
}

pub fn ark_point_to_g2_point(pt: &G2Affine) -> G2Point {
    G2Point {
        x: [
            U256::from_limbs(pt.x.c0.0 .0),
            U256::from_limbs(pt.x.c1.0 .0),
        ],
        y: [
            U256::from_limbs(pt.y.c0.0 .0),
            U256::from_limbs(pt.y.c1.0 .0),
        ],
    }
}

pub fn bigint_to_hex(bigint: &BigInteger256) -> String {
    let mut hex_string = String::new();
    for part in bigint.0.iter().rev() {
        write!(&mut hex_string, "{:016x}", part).unwrap();
    }
    hex_string
}

pub fn hex_string_to_biginteger256(hex_str: &str) -> BigInteger256 {
    let bytes = Vec::from_hex(hex_str).unwrap();

    assert!(bytes.len() <= 32, "Byte length exceeds 32 bytes");

    let mut padded_bytes = vec![0u8; 32];
    let start = 32 - bytes.len();
    padded_bytes[start..].copy_from_slice(&bytes);

    let mut limbs = [0u64; 4];
    for (i, chunk) in padded_bytes.chunks(8).rev().enumerate() {
        let mut array = [0u8; 8];
        let len = chunk.len().min(8);
        array[..len].copy_from_slice(&chunk[..len]); // Copy the bytes into the fixed-size array
        limbs[i] = u64::from_be_bytes(array);
    }

    BigInteger256::new(limbs)
}

#[derive(
    Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct Signature {
    pub g1_point: G1Point,
}

impl Signature {
    pub fn new_zero() -> Self {
        Self {
            g1_point: G1Point::zero(),
        }
    }

    pub fn sig(&self) -> G1Projective {
        G1Projective::from(self.clone().g1_point.to_ark_g1()) //self.g1_point.point
    }

    pub fn add(&mut self, other: &Signature) {
        self.g1_point.add(&other.g1_point);
    }

    pub fn verify(&self, pubkey: &G2Point, message: &[u8; 32]) -> Result<bool, AvsError> {
        println!("Verification Process Beginning...");
        let g2_gen = G2Point::generator();
        println!("Verification Process Mapping to Curve...");
        let msg_affine = map_to_curve(message);
        println!("Verification Process Creating Message Point...");
        let msg_point = G1Point::new(msg_affine.x, msg_affine.y);
        println!("Verification Process Creating Negative Point...");
        let neg_sig = self.g1_point.neg();
        println!("Verification Process Generating P...");
        let p: [G1Point; 2] = [msg_point, neg_sig];
        println!("Verification Process Generating Q...");
        let q: [G2Point; 2] = [pubkey.clone(), g2_gen];

        println!("Verification Process Generating P Projective...");
        let p_projective = [
            g1_point_to_ark_point(&p[0]).mul_bigint(Fr::one().0),
            g1_point_to_ark_point(&p[1]).mul_bigint(Fr::one().0),
        ];

        println!("Verification Process Generating Q Projective...");
        let q_projective = [
            g2_point_to_ark_point(&q[0]).mul_bigint(Fr::one().0),
            g2_point_to_ark_point(&q[1]).mul_bigint(Fr::one().0),
        ];

        println!("Verification Process Generating Inner Product...");
        let inner_product =
            PairingInnerProduct::<Bn254>::inner_product(&p_projective[..], &q_projective[..])
                .unwrap();
        println!("Verification Process Returning Result...");
        Ok(inner_product.0 == QuadExtField::one())
    }
}

// #[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
// pub struct PrivateKey {
//     pub key: Fq,
// }

pub type PrivateKey = Fr;

// impl PrivateKey {
//     pub fn new(key: Fq) -> Self {
//         Self { key }
//     }
//
//     pub fn from_big_integer256(key: BigInteger256) -> Self {
//         Self::new(Fq::from(key))
//     }
// }

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyPair {
    pub priv_key: PrivateKey,
    pub pub_key: G1Projective,
}

impl KeyPair {
    pub fn new(sk: PrivateKey) -> Result<Self, AvsError> {
        let pub_key_point_result = mul_by_generator_g1(sk.clone());

        match pub_key_point_result {
            Ok(pub_key_point) => {
                // println!("Public Key In KeyPair New: {:?}", pub_key_point);
                // println!("Public Key X: {:?}", pub_key_point.x.inverse().unwrap() * pub_key_point.z);
                // println!("Public Key Y: {:?}", pub_key_point.y.inverse().unwrap() * pub_key_point.z);
                Ok(Self {
                    priv_key: sk.clone(),
                    pub_key: pub_key_point,
                })
            },
            Err(_) => Err(AvsError::KeyError(
                "Failed to generate new key pair".to_string(),
            )),
        }
    }

    pub fn from_string(s: String) -> Result<Self, AvsError> {
        let bigint = hex_string_to_biginteger256(&s);
        let private_key = Fr::from(bigint);
        KeyPair::new(private_key)
    }

    pub fn gen_random() -> Result<Self, AvsError> {
        let mut rng = rand::thread_rng();
        let key = Fr::rand(&mut rng);
        KeyPair::new(key)
    }

    pub fn save_to_file(&self, path: &str, password: &str) -> Result<(), AvsError> {
        let mut sk_bytes = Vec::new();
        let _ = self.priv_key.serialize_compressed(&mut sk_bytes);

        let salt = SaltString::generate(thread_rng());
        let mut kdf_buf: [u8; 32] = Default::default();
        scrypt::scrypt(
            password.as_bytes(),
            salt.clone().as_str().as_bytes(),
            &Params::recommended(),
            &mut kdf_buf,
        )
        .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let password_hash =
            scrypt::password_hash::PasswordHash::generate(Scrypt, password, salt.as_salt())
                .map_err(|e| AvsError::KeyError(e.to_string()))?;

        let mut rng = thread_rng();
        let key: [u8; 32] = kdf_buf[..32]
            .try_into()
            .map_err(|_| AvsError::KeyError("Key conversion error".to_string()))?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
        let ciphertext: Vec<u8> = cipher
            .encrypt(&nonce, &sk_bytes[..])
            .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let crypto_struct = serde_json::json!({
            "encrypted_data": BASE64_STANDARD.encode(ciphertext),
            "nonce": BASE64_STANDARD.encode(nonce),
            "password_hash": BASE64_STANDARD.encode(password_hash.to_string()),
        });

        let encrypted_bls_struct = EncryptedBLSKeyJSONV3 {
            pub_key: G1Point::new(self.pub_key.x, self.pub_key.y),
            crypto: crypto_struct,
        };

        let data = serde_json::to_string(&encrypted_bls_struct)
            .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let dir = Path::new(path)
            .parent()
            .ok_or(AvsError::KeyError("Invalid path".to_string()))?;
        fs::create_dir_all(dir).map_err(|e| AvsError::KeyError(e.to_string()))?;
        fs::write(path, data).map_err(|e| AvsError::KeyError(e.to_string()))?;
        Ok(())
    }

    pub fn read_private_key_from_file(path: &str, password: &str) -> Result<Self, AvsError> {
        let key_store_contents =
            fs::read_to_string(path).map_err(|e| AvsError::KeyError(e.to_string()))?;
        let encrypted_bls_struct: EncryptedBLSKeyJSONV3 = serde_json::from_str(&key_store_contents)
            .map_err(|e| AvsError::KeyError(e.to_string()))?;

        let sk_bytes = BASE64_STANDARD
            .decode(
                encrypted_bls_struct.crypto["encrypted_data"]
                    .as_str()
                    .ok_or(AvsError::KeyError("Invalid data".to_string()))?,
            )
            .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let password_hash = BASE64_STANDARD
            .decode(
                encrypted_bls_struct.crypto["password_hash"]
                    .as_str()
                    .ok_or(AvsError::KeyError("Invalid data".to_string()))?,
            )
            .map(|p| {
                PasswordHashString::new(
                    std::str::from_utf8(&p).map_err(|_| password_hash::Error::Crypto)?,
                )
            })
            .map_err(|e| AvsError::KeyError(e.to_string()))?
            .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let nonce = BASE64_STANDARD
            .decode(
                encrypted_bls_struct.crypto["nonce"]
                    .as_str()
                    .ok_or(AvsError::KeyError("Invalid data".to_string()))?,
            )
            .map(|n| Nonce::clone_from_slice(&n[..]))
            .map_err(|e| AvsError::KeyError(e.to_string()))?;

        password_hash
            .password_hash()
            .verify_password(&[&Scrypt], password)
            .map_err(|e| AvsError::KeyError(e.to_string()))?;

        let salt = password_hash
            .salt()
            .ok_or(AvsError::KeyError("Invalid salt".to_string()))?
            .as_str();
        let mut kdf_buf: [u8; 32] = Default::default();
        scrypt::scrypt(
            password.as_bytes(),
            salt.as_ref(),
            &Params::recommended(),
            &mut kdf_buf,
        )
        .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let key: [u8; 32] = kdf_buf[..32]
            .try_into()
            .map_err(|_| AvsError::KeyError("Key conversion error".to_string()))?;
        let cipher = ChaCha20Poly1305::new(&key.into());
        let priv_key_bytes = cipher
            .decrypt(&nonce, &sk_bytes[..])
            .map_err(|e| AvsError::KeyError(e.to_string()))?;

        let priv_key = Fr::from_le_bytes_mod_order(&priv_key_bytes);

        let pair = KeyPair {
            priv_key,
            pub_key: G1Projective::from(encrypted_bls_struct.pub_key.to_ark_g1()),
        };
        Ok(pair)
    }

    pub fn sign_message(&self, message: &[u8; 32]) -> Signature {
        let sig_point = map_to_curve(message);
        let sig = sig_point.mul(self.priv_key);
        Signature {
            g1_point: G1Point::new(sig.x, sig.y),
        }
    }

    pub fn sign_hashed_to_curve_message(&self, g1_hashed_msg: &G1Point) -> Signature {
        let mut sig_point = g1_hashed_msg.clone();
        sig_point.mul(self.priv_key);
        Signature {
            g1_point: sig_point,
        }
    }

    pub fn get_pub_key_g2(&self) -> G2Point {
        let g2_gen = G2Affine::generator();
        // Scalar multiplication
        let result = g2_gen.mul_bigint(self.priv_key.0);
        // Convert result to affine form
        let g2_affine = G2Affine::from(result);
        G2Point::from_ark_g2(&g2_affine)
    }

    pub fn get_pub_key_g1(&self) -> G1Point {
        // let point = G1Point { point: self.pub_key};
        G1Point::new(self.pub_key.x, self.pub_key.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::bn::G1Projective;
    use ark_ff::{BigInt, Zero};
    use ark_ff::{BigInteger256, UniformRand};
    use gadget_common::sp_core::crypto::Ss58Codec;
    use hex::FromHex;
    use rand::{thread_rng, Rng, RngCore};

    #[tokio::test]
    async fn test_keypair_generation() {
        let keypair = KeyPair::gen_random().unwrap();

        // Check that the public key is not zero
        assert_ne!(keypair.pub_key, G1Projective::zero());
    }

    #[tokio::test]
    async fn test_signature_generation() {
        let keypair = KeyPair::gen_random().unwrap();

        let message = [0u8; 32];
        let signature = keypair.sign_message(&message);

        // Check that the signature is not zero
        assert_ne!(signature.g1_point, G1Point::zero());
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let keypair = KeyPair::gen_random().unwrap();
        let pub_key_g2 = keypair.get_pub_key_g2();
        // generate a random message
        let mut message = [0u8; 32];
        rand::thread_rng().fill(&mut message);

        let signature = keypair.sign_message(&message);

        let g1_projective = G1Projective::from(signature.g1_point.to_ark_g1());

        // Check that the signature is not zero
        assert_ne!(g1_projective, G1Projective::zero());
        let mut wrong_message = [0u8; 32];
        rand::thread_rng().fill(&mut wrong_message);

        // Check that the signature verifies
        assert!(signature.verify(&pub_key_g2, &message));
        assert!(!signature.verify(&pub_key_g2, &wrong_message))
    }

    #[tokio::test]
    async fn test_signature_verification_invalid() {
        let mut rng = thread_rng();
        let keypair = KeyPair::gen_random().unwrap();

        let mut message = [0u8; 32];
        rand::thread_rng().fill(&mut message);

        let signature = keypair.sign_message(&message);
        let g1_projective = G1Projective::from(signature.g1_point.to_ark_g1());

        // Check that the signature is not zero
        assert_ne!(g1_projective, G1Projective::zero());

        // Check that the signature does not verify with a different public key
        let different_pub_key = G2Point::rand(&mut rng);
        assert!(!signature.verify(&different_pub_key, &message));
    }

    #[tokio::test]
    async fn test_keypair_from_string() {
        let bigint = BigInt([
            12844100841192127628,
            7068359412155877604,
            5417847382009744817,
            1586467664616413849,
        ]);
        let hex_string = bigint_to_hex(&bigint);
        let converted_bigint = hex_string_to_biginteger256(&hex_string);
        assert_eq!(bigint, converted_bigint);
        let keypair_result_from_string = KeyPair::from_string(hex_string);
        let keypair_result_normal = KeyPair::new(Fr::from(bigint));

        let keypair_from_string = keypair_result_from_string.unwrap();
        let keypair_from_new = keypair_result_normal.unwrap();
        assert_eq!(keypair_from_new.priv_key, keypair_from_string.priv_key);
    }
}
