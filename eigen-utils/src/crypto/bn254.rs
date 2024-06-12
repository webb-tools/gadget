use crate::crypto::bls::G1Point;

use ark_bn254::{Fq as Bn254Fq, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField};

pub fn map_to_curve(digest: &[u8; 32]) -> G1Point {
    let one = Bn254Fq::one();
    let three = Bn254Fq::from(3u64);
    let mut x = Bn254Fq::from_be_bytes_mod_order(digest);
    loop {
        let x_cubed = x.pow([3]);
        let y = x_cubed + three;
        if let Some(y_sqrt) = y.sqrt() {
            return G1Point::new(x, y_sqrt);
        } else {
            x += one;
        }
    }
}

pub fn mul_by_generator_g1(a: &Bn254Fq) -> Bn254G1Affine {
    Bn254G1Affine::generator().mul_bigint(a.0).into_affine()
}

pub fn mul_by_generator_g2(a: &Bn254Fq) -> Bn254G2Affine {
    Bn254G2Affine::generator().mul_bigint(a.0).into_affine()
}
