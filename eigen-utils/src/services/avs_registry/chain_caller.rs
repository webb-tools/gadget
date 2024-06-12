use alloy_primitives::{Bytes, U256};

use async_trait::async_trait;
use eigen_contracts::OperatorStateRetriever;
use std::collections::HashMap;

use crate::avs_registry::reader::AvsRegistryChainReaderTrait;

use crate::crypto::bls::G1Point;
use crate::services::operator_info::OperatorInfoServiceTrait;
use crate::types::{
    bytes_to_quorum_ids, AvsError, OperatorAvsState, OperatorId, QuorumAvsState, QuorumNum,
    QuorumNums,
};
use crate::Config;

use super::{AvsRegistryServiceChainCaller, AvsRegistryServiceTrait};

#[async_trait]
impl<T, I> AvsRegistryServiceTrait for AvsRegistryServiceChainCaller<T, I>
where
    T: Config,
    I: OperatorInfoServiceTrait,
{
    async fn get_operators_avs_state_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> Result<HashMap<OperatorId, OperatorAvsState>, AvsError> {
        let mut operators_avs_state: HashMap<OperatorId, OperatorAvsState> = HashMap::new();

        let operators_stakes_in_quorums: Vec<Vec<OperatorStateRetriever::Operator>> = self
            .avs_registry_manager
            .get_operators_stake_in_quorums_at_block(quorum_numbers.clone(), block_number)
            .await
            .map_err(|e| {
                AvsError::OperatorError(format!("Failed to get operator state: {:?}", e))
            })?;

        let quorum_nums_vec: Vec<QuorumNum> = bytes_to_quorum_ids(&quorum_numbers);
        if operators_stakes_in_quorums.len() != quorum_nums_vec.clone().len() {
            log::error!("Number of quorums returned from GetOperatorsStakeInQuorumsAtBlock does not match number of quorums requested. Probably pointing to old contract or wrong implementation.");
        }

        for (quorum_idx, quorum_num) in quorum_nums_vec.iter().enumerate() {
            for operator in &operators_stakes_in_quorums[quorum_idx] {
                let info = self.get_operator_info(operator.operatorId).await?;
                let operator_stake = U256::from(operator.stake);
                if let Some(operator_avs_state) = operators_avs_state.get_mut(&operator.operatorId)
                {
                    operator_avs_state
                        .stake_per_quorum
                        .insert(quorum_num.clone(), operator_stake);
                } else if let Some(operator_info) = info {
                    let mut stake_per_quorum = HashMap::new();
                    stake_per_quorum.insert(quorum_num.clone(), operator_stake);
                    operators_avs_state.insert(
                        operator.operatorId,
                        OperatorAvsState {
                            operator_id: operator.operatorId,
                            operator_info,
                            stake_per_quorum,
                            block_number: block_number.try_into().unwrap(),
                        },
                    );
                }
            }
        }

        Ok(operators_avs_state)
    }

    async fn get_quorums_avs_state_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> Result<HashMap<QuorumNum, QuorumAvsState>, AvsError> {
        let operators_avs_state = self
            .get_operators_avs_state_at_block(quorum_numbers.clone(), block_number)
            .await?;

        let mut quorums_avs_state = HashMap::new();

        let quorum_num_vec: QuorumNums = bytes_to_quorum_ids(&quorum_numbers);
        for quorum_num in quorum_num_vec {
            let mut agg_pubkey_g1 = G1Point::zero();
            let mut total_stake = U256::from(0);

            for operator in operators_avs_state.values() {
                if let Some(stake) = operator.stake_per_quorum.get(&quorum_num) {
                    agg_pubkey_g1.add(&G1Point::from_ark_g1(
                        &operator.operator_info.pubkeys.g1_pubkey,
                    ));
                    total_stake += stake;
                }
            }

            quorums_avs_state.insert(
                quorum_num.clone(),
                QuorumAvsState {
                    quorum_number: quorum_num,
                    agg_pubkey_g1,
                    total_stake,
                    block_number: block_number.try_into().unwrap(),
                },
            );
        }

        Ok(quorums_avs_state)
    }

    async fn get_check_signatures_indices(
        &self,
        reference_block_number: u64,
        quorum_numbers: Bytes,
        non_signer_operator_ids: Vec<OperatorId>,
    ) -> Result<OperatorStateRetriever::CheckSignaturesIndices, AvsError> {
        self.avs_registry_manager
            .get_check_signatures_indices(
                reference_block_number.try_into().unwrap(),
                quorum_numbers,
                non_signer_operator_ids,
            )
            .await
            .map_err(|e| {
                AvsError::OperatorError(format!("Failed to get check signatures indices: {:?}", e))
            })
    }
}
