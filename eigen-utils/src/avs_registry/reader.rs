use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types::Filter;

use ark_bn254::{Fq as Bn254Fq, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_ff::{BigInt, PrimeField};
use eigen_contracts::RegistryCoordinator::OperatorSocketUpdate;
use eigen_contracts::{BlsApkRegistry, OperatorStateRetriever, RegistryCoordinator, StakeRegistry};
use std::collections::HashMap;

use crate::{types::*, Config};

use super::{AvsRegistryContractManager, AvsRegistryContractResult};

pub trait AvsRegistryChainReaderTrait {
    async fn get_quorum_count(&self) -> AvsRegistryContractResult<u8>;

    async fn get_operators_stake_in_quorums_at_current_block(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<Vec<Vec<OperatorStateRetriever::Operator>>>;

    async fn get_operators_stake_in_quorums_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> AvsRegistryContractResult<Vec<Vec<OperatorStateRetriever::Operator>>>;

    async fn get_operator_addrs_in_quorums_at_current_block(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<Vec<Vec<Address>>>;

    async fn get_operators_stake_in_quorums_of_operator_at_block(
        &self,
        operator_id: OperatorId,
        block_number: u64,
    ) -> AvsRegistryContractResult<(QuorumNums, Vec<Vec<OperatorStateRetriever::Operator>>)>;

    async fn get_operators_stake_in_quorums_of_operator_at_current_block(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<(QuorumNums, Vec<Vec<OperatorStateRetriever::Operator>>)>;

    async fn get_operator_stake_in_quorums_of_operator_at_current_block(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<HashMap<QuorumNum, StakeAmount>>;

    async fn get_check_signatures_indices(
        &self,
        reference_block_number: u32,
        quorum_numbers: Bytes,
        non_signer_operator_ids: Vec<OperatorId>,
    ) -> AvsRegistryContractResult<OperatorStateRetriever::CheckSignaturesIndices>;

    async fn get_operator_id(
        &self,
        operator_address: Address,
    ) -> AvsRegistryContractResult<OperatorId>;

    async fn get_operator_from_id(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<Address>;

    async fn is_operator_registered(
        &self,
        operator_address: Address,
    ) -> AvsRegistryContractResult<bool>;

    async fn query_existing_registered_operator_pubkeys(
        &self,
        start_block: u64,
        stop_block: u64,
        block_range: u64,
    ) -> AvsRegistryContractResult<(Vec<Address>, Vec<OperatorPubkeys>)>;

    async fn query_existing_registered_operator_sockets(
        &self,
        start_block: u64,
        stop_block: u64,
        block_range: u64,
    ) -> AvsRegistryContractResult<HashMap<OperatorId, Socket>>;
}

impl<T: Config> AvsRegistryChainReaderTrait for AvsRegistryContractManager<T> {
    async fn get_quorum_count(&self) -> AvsRegistryContractResult<u8> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        registry_coordinator
            .quorumCount()
            .call()
            .await
            .map(|count| count._0)
            .map_err(AvsError::from)
    }

    async fn get_operators_stake_in_quorums_at_current_block(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<Vec<Vec<OperatorStateRetriever::Operator>>> {
        let current_block = self.eth_client_http.get_block_number().await?;
        self.get_operators_stake_in_quorums_at_block(quorum_numbers, current_block)
            .await
    }

    async fn get_operators_stake_in_quorums_at_block(
        &self,
        quorum_numbers: Bytes,
        block_number: u64,
    ) -> AvsRegistryContractResult<Vec<Vec<OperatorStateRetriever::Operator>>> {
        let operator_state_retriever = OperatorStateRetriever::new(
            self.operator_state_retriever_addr,
            self.eth_client_http.clone(),
        );
        operator_state_retriever
            .getOperatorState_0(
                self.registry_coordinator_addr,
                quorum_numbers,
                block_number.try_into().unwrap(),
            )
            .call()
            .await
            .map(|ops| ops._0)
            .map_err(AvsError::from)
    }

    async fn get_operator_addrs_in_quorums_at_current_block(
        &self,
        quorum_numbers: Bytes,
    ) -> AvsRegistryContractResult<Vec<Vec<Address>>> {
        let current_block = self.eth_client_http.get_block_number().await?;
        let operator_state_retriever = OperatorStateRetriever::new(
            self.operator_state_retriever_addr,
            self.eth_client_http.clone(),
        );
        let operator_stakes = operator_state_retriever
            .getOperatorState_0(
                self.registry_coordinator_addr,
                quorum_numbers,
                current_block.try_into().unwrap(),
            )
            .call()
            .await
            .map(|ops| ops._0)?;

        let mut quorum_operator_addrs = Vec::new();
        for quorum in operator_stakes {
            let mut operator_addrs = Vec::new();
            for operator in quorum {
                operator_addrs.push(operator.operator);
            }
            quorum_operator_addrs.push(operator_addrs);
        }
        Ok(quorum_operator_addrs)
    }

    async fn get_operators_stake_in_quorums_of_operator_at_block(
        &self,
        operator_id: OperatorId,
        block_number: u64,
    ) -> AvsRegistryContractResult<(QuorumNums, Vec<Vec<OperatorStateRetriever::Operator>>)> {
        let operator_state_retriever = OperatorStateRetriever::new(
            self.operator_state_retriever_addr,
            self.eth_client_http.clone(),
        );
        let (quorum_bitmap, operator_stakes) = operator_state_retriever
            .getOperatorState_1(
                self.registry_coordinator_addr,
                operator_id,
                block_number.try_into().unwrap(),
            )
            .call()
            .await
            .map(|val| (val._0, val._1))?;
        let quorums = bitmap_to_quorum_ids(&quorum_bitmap);
        Ok((quorums, operator_stakes))
    }

    async fn get_operators_stake_in_quorums_of_operator_at_current_block(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<(QuorumNums, Vec<Vec<OperatorStateRetriever::Operator>>)> {
        let current_block = self.eth_client_http.get_block_number().await?;
        self.get_operators_stake_in_quorums_of_operator_at_block(operator_id, current_block)
            .await
    }

    async fn get_operator_stake_in_quorums_of_operator_at_current_block(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<HashMap<QuorumNum, StakeAmount>> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let quorum_bitmap = registry_coordinator
            .getCurrentQuorumBitmap(operator_id)
            .call()
            .await
            .map(|val| val._0)?;

        let stake_registry =
            StakeRegistry::new(self.stake_registry_addr, self.eth_client_http.clone());
        let quorums = bitmap_to_quorum_ids(&quorum_bitmap);
        let mut quorum_stakes = HashMap::new();
        for quorum in quorums {
            let stake = stake_registry
                .getCurrentStake(operator_id, quorum.0)
                .call()
                .await
                .map(|val| val._0)?;

            quorum_stakes.insert(quorum, U256::from(stake));
        }
        Ok(quorum_stakes)
    }

    async fn get_check_signatures_indices(
        &self,
        reference_block_number: u32,
        quorum_numbers: Bytes,
        non_signer_operator_ids: Vec<OperatorId>,
    ) -> AvsRegistryContractResult<OperatorStateRetriever::CheckSignaturesIndices> {
        let operator_state_retriever = OperatorStateRetriever::new(
            self.operator_state_retriever_addr,
            self.eth_client_http.clone(),
        );
        operator_state_retriever
            .getCheckSignaturesIndices(
                self.registry_coordinator_addr,
                reference_block_number,
                quorum_numbers,
                non_signer_operator_ids,
            )
            .call()
            .await
            .map(|val| val._0)
            .map_err(AvsError::from)
    }

    async fn get_operator_id(
        &self,
        operator_address: Address,
    ) -> AvsRegistryContractResult<OperatorId> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        registry_coordinator
            .getOperatorId(operator_address)
            .call()
            .await
            .map(|val| val._0)
            .map_err(AvsError::from)
    }

    async fn get_operator_from_id(
        &self,
        operator_id: OperatorId,
    ) -> AvsRegistryContractResult<Address> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        registry_coordinator
            .getOperatorFromId(operator_id)
            .call()
            .await
            .map(|val| val._0)
            .map_err(AvsError::from)
    }

    async fn is_operator_registered(
        &self,
        operator_address: Address,
    ) -> AvsRegistryContractResult<bool> {
        let registry_coordinator =
            RegistryCoordinator::new(self.registry_coordinator_addr, self.eth_client_http.clone());
        let operator_status = registry_coordinator
            .getOperatorStatus(operator_address)
            .call()
            .await
            .map(|val| val._0)?;

        Ok(operator_status == 1)
    }

    async fn query_existing_registered_operator_pubkeys(
        &self,
        start_block: u64,
        stop_block: u64,
        block_range: u64,
    ) -> AvsRegistryContractResult<(Vec<Address>, Vec<OperatorPubkeys>)> {
        let mut operator_addresses = Vec::new();
        let mut operator_pubkeys = Vec::new();

        for i in (start_block..=stop_block).step_by(block_range as usize) {
            let to_block = (i + block_range - 1).min(stop_block);

            let filter = Filter::new()
                .from_block(i)
                .to_block(to_block)
                .event("NewPubkeyRegistration")
                .address(self.bls_apk_registry_addr);
            let logs = self.eth_client_http.get_logs(&filter).await?;

            for log in logs {
                let maybe_pub_key_reg = log
                    .log_decode::<BlsApkRegistry::NewPubkeyRegistration>()
                    .ok();

                if let Some(pub_key_reg) = maybe_pub_key_reg {
                    let data = pub_key_reg.data();
                    operator_addresses.push(data.operator);
                    let g1_pt: Bn254G1Affine = Bn254G1Affine::get_point_from_x_unchecked(
                        Bn254Fq::from_bigint(BigInt::new(data.pubkeyG1.X.into_limbs())).unwrap(),
                        true,
                    )
                    .unwrap();
                    let g2_pt: Bn254G2Affine = Bn254G2Affine::identity();
                    operator_pubkeys.push(OperatorPubkeys {
                        g1_pubkey: g1_pt,
                        g2_pubkey: g2_pt,
                    });
                }
            }
        }

        Ok((operator_addresses, operator_pubkeys))
    }

    async fn query_existing_registered_operator_sockets(
        &self,
        start_block: u64,
        stop_block: u64,
        block_range: u64,
    ) -> AvsRegistryContractResult<HashMap<OperatorId, Socket>> {
        let mut operator_id_to_socket_map = HashMap::new();

        let start = start_block;
        let mut end = stop_block;
        if start_block == 0 && stop_block == 0 {
            end = self.eth_client_http.get_block_number().await? as u64;
        }

        for i in (start..=end).step_by(block_range as usize) {
            let to_block = (i + block_range - 1).min(end);
            let filter = Filter::new()
                .from_block(i)
                .to_block(to_block)
                .address(self.registry_coordinator_addr)
                .event("OperatorSocketUpdate");
            let logs = self.eth_client_http.get_logs(&filter).await?;

            for log in logs {
                let maybe_op_socket_update = log.log_decode::<OperatorSocketUpdate>().ok();

                if let Some(op_socket) = maybe_op_socket_update {
                    let data = op_socket.data();
                    operator_id_to_socket_map.insert(data.operatorId, data.socket.clone());
                }
            }
        }

        Ok(operator_id_to_socket_map)
    }
}
