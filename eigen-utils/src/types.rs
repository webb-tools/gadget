use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_transport::RpcError;
use alloy_transport::TransportErrorKind;

use ark_bn254::{Fq as Bn254Fq, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_ec::AffineRepr;

use ark_ff::BigInt;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Compress;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use thiserror::Error;

use crate::crypto::bls;
use crate::crypto::bls::G1Point;
use crate::crypto::bls::KeyPair;
use crate::crypto::bls::Signature;
use crate::utils::*;

pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

pub type TaskIndex = u32;
pub type TaskResponseDigest = B256;
pub type TaskResponse = Box<dyn std::any::Any>;

type TaskResponseHashFunction = fn(TaskResponse) -> TaskResponseDigest;

#[derive(Debug)]
pub struct SignedTaskResponseDigest {
    task_response: TaskResponse,
    bls_signature: bls::Signature,
    operator_id: OperatorId,
    signature_verification_error_c: Sender<anyhow::Error>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operator {
    pub address: Address,
    pub earnings_receiver_address: Address,
    pub delegation_approver_address: Address,
    pub staker_opt_out_window_blocks: u32,
    pub metadata_url: String,
}

impl Operator {
    pub async fn validate(&self) -> Result<(), AvsError> {
        // if !is_valid_ethereum_address(&self.address) {
        //     return Err(AvsError::InvalidOperatorAddress);
        // }
        // if !is_valid_ethereum_address(&self.earnings_receiver_address) {
        //     return Err(AvsError::InvalidEarningsReceiverAddress);
        // }
        // if self.delegation_approver_address != ZERO_ADDRESS
        //     && !is_valid_ethereum_address(&self.delegation_approver_address)
        // {
        //     return Err(AvsError::InvalidDelegationApproverAddress);
        // }
        check_if_url_is_valid(&self.metadata_url)?;
        let body = read_public_url(&self.metadata_url).await?;
        let operator_metadata: OperatorMetadata =
            serde_json::from_slice(&body).map_err(|_| AvsError::UnmarshalOperatorMetadata)?;
        operator_metadata.validate().await?;
        Ok(())
    }
}

// Socket represents the operator's socket address, which is registered onchain
// TODO: this could have multiple formats... do we really want to use a custom type for this?
// it could be ip:port, or just port, or ip:port:port if 2 ports are needed (like in eigenda's cast)
// or whatever an avs decides to use
pub type Socket = String;

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OperatorInfo {
    socket: Socket,
    pubkeys: OperatorPubkeys,
}

#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct OperatorPubkeys {
    pub g1_pubkey: Bn254G1Affine,
    pub g2_pubkey: Bn254G2Affine,
}

impl OperatorPubkeys {
    pub fn to_contract_pubkeys(&self) -> (Bn254G1Affine, Bn254G2Affine) {
        let mut ser_buf = vec![0; self.g1_pubkey.serialized_size(Compress::Yes)];
        self.g1_pubkey.serialize_compressed(&mut ser_buf);

        let mut ser_buf2 = vec![0; self.g2_pubkey.serialized_size(Compress::Yes)];
        self.g2_pubkey.serialize_compressed(&mut ser_buf2);
        (
            Bn254G1Affine::deserialize_compressed::<&[u8]>(ser_buf.as_ref()).unwrap(),
            Bn254G2Affine::deserialize_compressed::<&[u8]>(ser_buf2.as_ref()).unwrap(),
        )
    }
}

pub type OperatorAddr = Address;
pub type StakeAmount = U256;
pub type OperatorId = B256;

pub fn operator_id_from_g1_pubkey(pubkey: &G1Point) -> OperatorId {
    let pubkey: Bn254G1Affine = Bn254G1Affine::new(
        Bn254Fq::from(BigInt::new(pubkey.x.into_limbs())),
        Bn254Fq::from(BigInt::new(pubkey.y.into_limbs())),
    );

    let mut x_bytes: Vec<u8> = vec![0; pubkey.x.serialized_size(Compress::Yes)];
    pubkey.x.serialize_compressed(&mut x_bytes).unwrap();

    let mut y_bytes: Vec<u8> = vec![0; pubkey.y.serialized_size(Compress::Yes)];
    pubkey.y.serialize_compressed(&mut y_bytes).unwrap();

    keccak256([&x_bytes[..], &y_bytes[..]].concat())
}

pub fn operator_id_from_contract_g1_pubkey(pubkey: G1Point) -> OperatorId {
    operator_id_from_g1_pubkey(&pubkey)
}

pub fn operator_id_from_key_pair(key_pair: &KeyPair) -> OperatorId {
    operator_id_from_g1_pubkey(&key_pair.pub_key)
}

pub fn sign_hashed_to_curve_message(pt: G1Point, key_pair: &KeyPair) -> Result<Signature, ()> {
    let ark_pt: Bn254G1Affine = Bn254G1Affine::new(
        Bn254Fq::from(BigInt::new(pt.x.into_limbs())),
        Bn254Fq::from(BigInt::new(pt.y.into_limbs())),
    );
    let sig = ark_pt.mul_bigint(&key_pair.priv_key.key.0);
    let sig_point = G1Point {
        x: U256::from_limbs(sig.x.0 .0),
        y: U256::from_limbs(sig.y.0 .0),
    };
    Ok(Signature {
        g1_point: sig_point,
    })
}

pub type QuorumNums = Vec<QuorumNum>;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct QuorumNum(pub u8);

impl QuorumNum {
    pub fn underlying_type(&self) -> u8 {
        self.0
    }
}

pub type QuorumThresholdPercentages = Vec<QuorumThresholdPercentage>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumThresholdPercentage(pub u8);

impl QuorumThresholdPercentage {
    pub fn underlying_type(&self) -> u8 {
        self.0
    }
}

pub type BlockNum = u32;

#[derive(Debug, Clone, PartialEq)]
pub struct OperatorAvsState {
    operator_id: OperatorId,
    operator_info: OperatorInfo,
    stake_per_quorum: HashMap<QuorumNum, StakeAmount>,
    block_number: BlockNum,
}

const MAX_NUMBER_OF_QUORUMS: usize = 192;

pub fn bitmap_to_quorum_ids(bitmap: &U256) -> Vec<QuorumNum> {
    let mut quorum_ids = Vec::new();
    for i in 0..MAX_NUMBER_OF_QUORUMS {
        if bitmap.bit(i) {
            quorum_ids.push(QuorumNum(i as u8));
        }
    }
    quorum_ids
}

#[derive(Debug, Clone, PartialEq)]
pub struct QuorumAvsState {
    quorum_number: QuorumNum,
    total_stake: StakeAmount,
    agg_pubkey_g1: Bn254G1Affine,
    block_number: BlockNum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorMetadata {
    name: String,
    website: String,
    description: String,
    logo: String,
    twitter: Option<String>,
}

impl OperatorMetadata {
    pub async fn validate(&self) -> Result<(), AvsError> {
        validate_text(&self.name).map_err(|_e| AvsError::InvalidName)?;
        validate_text(&self.description).map_err(|_e| AvsError::InvalidDescription)?;
        if self.logo.is_empty() {
            return Err(AvsError::LogoRequired);
        }
        is_image_url(&self.logo).await?;
        if !self.website.is_empty() {
            check_if_url_is_valid(&self.website)?;
        }
        if let Some(twitter) = &self.twitter {
            check_if_valid_twitter_url(twitter)?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum AvsError {
    #[error("invalid operator address")]
    InvalidOperatorAddress,
    #[error("invalid earnings receiver address")]
    InvalidEarningsReceiverAddress,
    #[error("invalid delegation approver address")]
    InvalidDelegationApproverAddress,
    #[error("invalid metadata URL")]
    InvalidMetadataUrl,
    #[error("reading metadata URL response")]
    ReadingMetadataUrlResponse,
    #[error("unmarshal operator metadata")]
    UnmarshalOperatorMetadata,
    #[error("logo required")]
    LogoRequired,
    #[error("invalid website URL")]
    InvalidWebsiteUrl,
    #[error("invalid name")]
    InvalidName,
    #[error("invalid description")]
    InvalidDescription,
    #[error("invalid Twitter URL")]
    InvalidTwitterUrl,
    #[error("invalid url validation")]
    InvalidUrl(#[from] UrlError),
    #[error("alloy contract error")]
    ContractError(#[from] alloy_contract::Error),
    #[error("alloy signer error")]
    SignerError(#[from] alloy_signer::Error),
    #[error("rpc error")]
    RpcError(#[from] RpcError<TransportErrorKind>),
}