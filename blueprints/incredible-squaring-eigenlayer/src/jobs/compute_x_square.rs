#![allow(dead_code)]
use crate::contexts::client::SignedTaskResponse;
use crate::contexts::x_square::EigenSquareContext;
use crate::{IncredibleSquaringTaskManager, INCREDIBLE_SQUARING_TASK_MANAGER_ABI_STRING};
use alloy_primitives::keccak256;
use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolType;
use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use color_eyre::Result;
use eigensdk::crypto_bls::{BlsKeyPair, OperatorId};
use gadget_sdk::keystore::BackendExt;
use gadget_sdk::{error, info, job};
use std::{convert::Infallible, ops::Deref};
use IncredibleSquaringTaskManager::TaskResponse;

/// Returns x^2 saturating to [`u64::MAX`] if overflow occurs.
#[job(
    id = 0,
    params(number_to_be_squared, task_created_block, quorum_numbers, quorum_threshold_percentage, task_index),
    result(_),
    event_listener(
        listener = EvmContractEventListener<EigenSquareContext>(
            instance = IncredibleSquaringTaskManager,
            abi = INCREDIBLE_SQUARING_TASK_MANAGER_ABI_STRING,
        ),
        event = IncredibleSquaringTaskManager::NewTaskCreated,
        pre_processor = convert_event_to_inputs,
        post_processor = noop,
    ),
)]
pub async fn xsquare_eigen(
    ctx: EigenSquareContext,
    number_to_be_squared: U256,
    task_created_block: u32,
    quorum_numbers: Bytes,
    quorum_threshold_percentage: u8,
    task_index: u32,
) -> Result<u32, Infallible> {
    let client = ctx.client.clone();
    let env = ctx.env.clone();

    // Calculate our response to job
    let task_response = TaskResponse {
        referenceTaskIndex: task_index,
        numberSquared: number_to_be_squared.saturating_pow(U256::from(2u32)),
    };

    let bls_key_pair = match env.keystore() {
        Ok(keystore) => {
            let pair = keystore.bls_bn254_key();
            match pair {
                Ok(pair) => pair,
                Err(e) => {
                    error!("Failed to get BLS key pair: {:#?}", e);
                    return Ok(1);
                }
            }
        }
        Err(e) => {
            error!("Failed to get keystore: {:#?}", e);
            return Ok(1);
        }
    };

    let operator_id: OperatorId = operator_id_from_key(bls_key_pair.clone());

    // Sign the Hashed Message and send it to the BLS Aggregator
    let msg_hash = keccak256(<TaskResponse as SolType>::abi_encode(&task_response));
    let signed_response = SignedTaskResponse {
        task_response,
        signature: bls_key_pair.sign_message(msg_hash.as_ref()),
        operator_id,
    };

    info!(
        "Sending signed task response to BLS Aggregator: {:#?}",
        signed_response
    );
    if let Err(e) = client.send_signed_task_response(signed_response).await {
        error!("Failed to send signed task response: {:?}", e);
        return Ok(0);
    }

    Ok(1)
}

/// Generate the Operator ID from the BLS Keypair
pub fn operator_id_from_key(key: BlsKeyPair) -> OperatorId {
    let pub_key = key.public_key();
    let pub_key_affine = pub_key.g1();

    let x_int: num_bigint::BigUint = pub_key_affine.x.into();
    let y_int: num_bigint::BigUint = pub_key_affine.y.into();

    let x_bytes = x_int.to_bytes_be();
    let y_bytes = y_int.to_bytes_be();

    keccak256([x_bytes, y_bytes].concat())
}

/// Converts the event to inputs.
///
/// Uses a tuple to represent the return type because
/// the macro will index all values in the #[job] function
/// and parse the return type by the index.
pub fn convert_event_to_inputs(
    event: IncredibleSquaringTaskManager::NewTaskCreated,
    _index: u32,
) -> (U256, u32, Bytes, u8, u32) {
    let task_index = event.taskIndex;
    let number_to_be_squared = event.task.numberToBeSquared;
    let task_created_block = event.task.taskCreatedBlock;
    let quorum_numbers = event.task.quorumNumbers;
    let quorum_threshold_percentage = event.task.quorumThresholdPercentage.try_into().unwrap();
    (
        number_to_be_squared,
        task_created_block,
        quorum_numbers,
        quorum_threshold_percentage,
        task_index,
    )
}

/// Helper for converting a PrimeField to its U256 representation for Ethereum compatibility
/// (U256 reads data as big endian)
pub fn point_to_u256(point: Fq) -> U256 {
    let point = point.into_bigint();
    let point_bytes = point.to_bytes_be();
    U256::from_be_slice(&point_bytes[..])
}
