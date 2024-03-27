use gadget_common::channels::{MaybeReceiver, MaybeSender, MaybeSenderReceiver};
use gadget_common::prelude::AccountId32;
use gadget_common::JobError;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use sp_core::ecdsa;
use sp_core::ecdsa::Signature;
use std::sync::Arc;
use wsts::common::{PolyCommitment, PublicNonce, SignatureShare};
use wsts::v2::PartyState;
use wsts::Scalar;

#[derive(Serialize, Deserialize, Debug)]
pub enum FrostMessage {
    Keygen {
        party_id: u32,
        shares: HashMap<u32, Scalar>,
        key_ids: Vec<u32>,
        poly_commitment: PolyCommitment,
    },
    Signing {
        party_id: u32,
        key_ids: Vec<u32>,
        nonce: PublicNonce,
    },
    SigningFinal {
        party_id: u32,
        signature_share: SignatureShare,
    },
    PublicKeyBroadcast {
        party_id: u32,
        combined_public_key: Vec<u8>,
        signature_of_public_key: Signature,
    },
}

impl FrostMessage {
    pub fn party_id(&self) -> u32 {
        match self {
            FrostMessage::Keygen { party_id, .. } => *party_id,
            FrostMessage::Signing { party_id, .. } => *party_id,
            FrostMessage::SigningFinal { party_id, .. } => *party_id,
            FrostMessage::PublicKeyBroadcast { party_id, .. } => *party_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
/// Used for preserving the state of the Keygen. Should be stored in a keystore.
///
/// Used in signing
pub struct FrostState {
    pub public_key: HashMap<u32, PolyCommitment>,
    pub party: Arc<PartyState>,
}

pub fn validate_parameters(n: u32, k: u32, t: u32) -> Result<(), JobError> {
    if k % n != 0 {
        return Err(JobError {
            reason: "K % N != 0".to_string(),
        });
    }

    if k == 0 {
        return Err(JobError {
            reason: "K == 0".to_string(),
        });
    }

    if n <= t {
        return Err(JobError {
            reason: "N <= T".to_string(),
        });
    }

    Ok(())
}

/// Returns a Vec of indices that denotes which indexes within the public key vector
/// are owned by which party.
///
/// E.g., if n=4 and k=10,
///
/// let party_key_ids: Vec<Vec<u32>> = [
///     [0, 1, 2].to_vec(),
///     [3, 4].to_vec(),
///     [5, 6, 7].to_vec(),
///     [8, 9].to_vec(),
/// ]
///
/// In the above case, we go up from 0..=9 possible key ids since k=10, and
/// we have 4 grouping since n=4. We need to generalize this below
pub fn generate_party_key_ids(n: u32, k: u32) -> Vec<Vec<u32>> {
    let mut result = Vec::with_capacity(n as usize);
    let ids_per_party = k / n;
    let mut start = 0;

    for _ in 0..n {
        let end = start + ids_per_party;
        let ids = (start..end).collect();
        result.push(ids);
        start = end;
    }

    result
}

impl MaybeSenderReceiver for FrostMessage {
    fn maybe_sender(&self) -> MaybeSender {
        MaybeSender::SomeoneElse(self.party_id())
    }

    fn maybe_receiver(&self) -> MaybeReceiver {
        // All messages are broadcasted for this protocol
        MaybeReceiver::Broadcast
    }
}

pub fn account_id_32_to_ecdsa_33(account_id: AccountId32) -> ecdsa::Public {
    let mut ret = [0u8; 33];
    let subset = &mut ret[1..];
    subset.copy_from_slice(account_id.0.as_slice());
    ecdsa::Public(ret)
}
