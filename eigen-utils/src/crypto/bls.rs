/// https://hackmd.io/@jpw/bn254
use alloy_primitives::U256;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::{BigInt, QuadExtField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::One;
use ark_std::UniformRand;
use base64::prelude::*;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use rand::thread_rng;
use scrypt::password_hash::{PasswordHashString, Salt};
use scrypt::{Params, Scrypt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::types::AvsError;

use super::bn254::map_to_curve;
use super::pairing_products::{InnerProduct, PairingInnerProduct};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedBLSKeyJSONV3 {
    pub pub_key: String,
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
        Self {
            x: U256::from_limbs(x.0 .0),
            y: U256::from_limbs(y.0 .0),
        }
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
        let neg_affine = -affine;
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

    pub fn mul(&mut self, scalar: Fq) {
        let affine = g1_point_to_ark_point(self);

        let pt = affine.mul_bigint(scalar.0).into_affine();
        *self = ark_point_to_g1_point(&pt);
    }

    pub fn from_ark_g1(ark_g1: &G1Affine) -> Self {
        ark_point_to_g1_point(ark_g1)
    }

    pub fn to_ark_g1(&self) -> G1Affine {
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
    G1Affine::new(
        Fq::from(BigInt(pt.x.into_limbs())),
        Fq::from(BigInt(pt.y.into_limbs())),
    )
}

pub fn ark_point_to_g1_point(pt: &G1Affine) -> G1Point {
    G1Point {
        x: U256::from_limbs(pt.x.0 .0),
        y: U256::from_limbs(pt.y.0 .0),
    }
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

    pub fn add(&mut self, other: &Signature) {
        self.g1_point.add(&other.g1_point);
    }

    pub fn verify(&self, pubkey: &G2Point, message: &[u8; 32]) -> Result<bool, AvsError> {
        let g2_gen = G2Point::generator();
        let msg_point = map_to_curve(message);
        let neg_sig = self.g1_point.neg();
        let p: [G1Point; 2] = [msg_point, neg_sig];
        let q: [G2Point; 2] = [pubkey.clone(), g2_gen];

        let p_projective = [
            g1_point_to_ark_point(&p[0]).mul_bigint(Fr::one().0),
            g1_point_to_ark_point(&p[1]).mul_bigint(Fr::one().0),
        ];

        let q_projective = [
            g2_point_to_ark_point(&q[0]).mul_bigint(Fr::one().0),
            g2_point_to_ark_point(&q[1]).mul_bigint(Fr::one().0),
        ];

        let inner_product =
            PairingInnerProduct::<Bn254>::inner_product(&p_projective[..], &q_projective[..])
                .unwrap();
        Ok(inner_product.0 == QuadExtField::one())
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey {
    pub key: Fq,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeyPair {
    pub priv_key: PrivateKey,
    pub pub_key: G1Point,
}

impl KeyPair {
    pub fn new(sk: &PrivateKey) -> Self {
        let pub_key_point = G1Affine::generator().mul_bigint(sk.key.0).into_affine();
        Self {
            priv_key: sk.clone(),
            pub_key: ark_point_to_g1_point(&pub_key_point),
        }
    }

    pub fn gen_random() -> Result<Self, AvsError> {
        let mut rng = rand::thread_rng();
        let key = Fq::rand(&mut rng);
        let priv_key = PrivateKey { key };
        Ok(Self::new(&priv_key))
    }

    pub fn save_to_file(&self, path: &str, password: &str) -> Result<(), AvsError> {
        let mut sk_bytes = vec![0; self.priv_key.compressed_size()];
        let _ = self.priv_key.serialize_compressed(&mut sk_bytes);

        let mut kdf_buf = Vec::new();
        scrypt::scrypt(
            password.as_bytes(),
            &[],
            &Params::recommended(),
            &mut kdf_buf[..],
        )
        .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let password_hash = scrypt::password_hash::PasswordHash::generate(
            Scrypt,
            password,
            Salt::from_b64("").unwrap(),
        )
        .unwrap();

        let mut rng = thread_rng();
        let key: [u8; 32] = kdf_buf[..32].try_into().unwrap();
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
        let ciphertext: Vec<u8> = cipher
            .encrypt(&nonce, b"plaintext message".as_ref())
            .unwrap();
        let crypto_struct = serde_json::json!({
            "encrypted_data": BASE64_STANDARD.encode(ciphertext),
            "nonce": BASE64_STANDARD.encode(nonce),
            "password_hash": BASE64_STANDARD.encode(password_hash.hash.unwrap().as_bytes()),
        });

        let encrypted_bls_struct = EncryptedBLSKeyJSONV3 {
            pub_key: format!("{:?}", self.pub_key),
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

        if encrypted_bls_struct.pub_key.is_empty() {
            return Err(AvsError::KeyError(
                "Invalid BLS key file. PubKey field not found.".to_string(),
            ));
        }

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
            .map(|p| PasswordHashString::new(std::str::from_utf8(&p).unwrap()))
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

        let mut kdf_buf = Vec::new();
        scrypt::scrypt(
            password.as_bytes(),
            &[],
            &Params::recommended(),
            &mut kdf_buf[..],
        )
        .map_err(|e| AvsError::KeyError(e.to_string()))?;
        let key: [u8; 32] = kdf_buf[..32].try_into().unwrap();
        let cipher = ChaCha20Poly1305::new(&key.into());
        let priv_key_bytes = cipher
            .decrypt(&nonce, &sk_bytes[..])
            .map_err(|e| AvsError::KeyError(e.to_string()))?;

        let priv_key = Fq::from_le_bytes_mod_order(&priv_key_bytes);
        Ok(Self::new(&PrivateKey { key: priv_key }))
    }

    pub fn sign_message(&self, message: &[u8; 32]) -> Signature {
        let mut sig_point = map_to_curve(message);
        sig_point.mul(self.priv_key.key);
        Signature {
            g1_point: sig_point,
        }
    }

    pub fn sign_hashed_to_curve_message(&self, g1_hashed_msg: &G1Point) -> Signature {
        let mut sig_point = g1_hashed_msg.clone();
        sig_point.mul(self.priv_key.key);
        Signature {
            g1_point: sig_point,
        }
    }

    pub fn get_pub_key_g2(&self) -> G2Point {
        let mut pub_key_g2_point = G2Point::generator();
        pub_key_g2_point.mul(self.priv_key.key);

        pub_key_g2_point
    }

    pub fn get_pub_key_g1(&self) -> &G1Point {
        &self.pub_key
    }
}
