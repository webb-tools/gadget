use crate::error::BlsError;
use alloy_primitives::U256;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{BigInteger256, Field, One, PrimeField};
use hex::FromHex;
use std::fmt::Write;
use std::ops::{Add, Mul};
pub fn new_fp_element(x: BigInteger256) -> Fq {
    Fq::from(x)
}

fn new_fp2_element(a: BigInteger256, b: BigInteger256) -> Fq2 {
    Fq2::new(Fq::from(a), Fq::from(b))
}

type PrivateKey = Fr;

#[derive(Debug, Clone)]
pub struct Signature {
    g1_point: G1Point,
}

impl Signature {
    pub fn new_zero_signature() -> Self {
        return Signature {
            g1_point: G1Point::new_zero_g1_point(),
        };
    }

    pub fn get_g1_point(&self) -> G1Point {
        self.g1_point.clone()
    }

    pub fn sig(&self) -> G1Projective {
        self.g1_point.point
    }

    /// Verify BLS signature using BN254
    /// TODO : test this . 99% this is wrong
    pub fn verify_signature(&self, pubkey: G2Projective, message: &[u8; 32]) -> bool {
        let msg_hash = hash_to_g1(message);
        let g1_affine = self.g1_point.point.into_affine();

        let g2_affine = pubkey.into_affine();

        let generator = get_g2_generator().unwrap();
        let pairing_left = Bn254::pairing(g1_affine, generator);

        let pairing_right = Bn254::pairing(msg_hash, g2_affine);

        pairing_left == pairing_right
    }
}

fn hash_to_g1(digest: &[u8; 32]) -> G1Affine {
    let one = Fq::one();
    let three = Fq::from(3u64);
    let mut x = Fq::from_le_bytes_mod_order(digest);

    loop {
        let x_cubed = x.square() * x;
        let y_squared = x_cubed + three;

        if let Some(y) = y_squared.sqrt() {
            let point = G1Projective::new(x, y, Fq::one());
            return point.into_affine();
        } else {
            x += &one;
        }
    }
}
pub struct KeyPair {
    priv_key: PrivateKey,
    pub_key: G1Projective,
}

impl KeyPair {
    pub fn new(key: PrivateKey) -> Result<Self, BlsError> {
        let priv_key_projective_cconfig_result = mul_by_generator_g1(key);

        match priv_key_projective_cconfig_result {
            Ok(priv_key_projective_cconfig) => {
                return Ok(Self {
                    priv_key: key,
                    pub_key: priv_key_projective_cconfig,
                });
            }
            Err(_) => return Err(BlsError::MulByG1Projective),
        }
    }

    pub fn from_string(s: String) -> Result<Self, BlsError> {
        let bigint_key = hex_string_to_biginteger256(&s);
        let key = Fr::from(bigint_key);
        KeyPair::new(key)
    }

    pub fn sign_hashes_to_curve_message(&self, g1_hashes_msg: G1Projective) -> Signature {
        let sig = g1_hashes_msg.mul(self.priv_key);

        Signature {
            g1_point: G1Point { point: sig },
        }
    }

    pub fn get_pub_key_g1(&self) -> G1Projective {
        self.pub_key
    }

    pub fn get_pub_key_g2(&self) -> Result<G2Projective, BlsError> {
        let mul_result = mul_by_generator_g2(self.priv_key);

        match mul_result {
            Ok(mul) => Ok(mul),
            Err(_) => return Err(BlsError::MulByG2Projective),
        }
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

#[derive(Debug, Clone)]
pub struct G1Point {
    pub point: G1Projective,
}

#[derive(Debug, Clone)]
pub struct G2Point {
    pub point: G2Projective,
}

impl G2Point {
    // Function to create a new G2Point from x and y coordinates, where each coordinate is a pair of BigIntegers
    pub fn new(x: (BigInteger256, BigInteger256), y: (BigInteger256, BigInteger256)) -> Self {
        // Convert x and y to Fq2 elements
        let x_elem = new_fp2_element(x.1, x.0);
        let y_elem = new_fp2_element(y.1, y.0);

        // Create a new G2 point in projective coordinates
        let point = G2Projective::new(x_elem, y_elem, Fq2::one()); // Z coordinate is set to 1

        G2Point { point }
    }

    pub fn add(&mut self, p2: G2Point) -> G2Point {
        let added_point = self.point.add(p2.point);
        G2Point { point: added_point }
    }

    pub const fn zero() -> Self {
        G2Point::new(
            (
                u256_to_bigint256(U256::from(0)),
                u256_to_bigint256(U256::from(0)),
            ),
            (
                u256_to_bigint256(U256::from(0)),
                u256_to_bigint256(U256::from(0)),
            ),
        )
    }
}

impl G1Point {
    // Function to create a new G1Point from x and y coordinates
    pub fn new(x: BigInteger256, y: BigInteger256) -> Self {
        // Convert x and y to field elements
        let x_elem = new_fp_element(x);
        let y_elem = new_fp_element(y);

        // Create a new G1 point in projective coordinates
        let point = G1Projective::new(x_elem, y_elem, Fq::one()); // Z coordinate is set to 1

        G1Point { point }
    }

    pub fn add(&mut self, p2: G1Point) -> G1Point {
        let added_point = self.point.add(p2.point);
        G1Point { point: added_point }
    }

    pub const fn zero() -> Self {
        G1Point::new(
            u256_to_bigint256(U256::from(0)),
            u256_to_bigint256(U256::from(0)),
        )
    }
}
