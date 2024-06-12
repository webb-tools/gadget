use crate::types::*;
use crate::Config;

use alloy_primitives::{Address, U256};

use alloy_rpc_types::TransactionReceipt;

use async_trait::async_trait;

use eigen_contracts::DelegationManager;
use eigen_contracts::StrategyManager;

use super::{reader::ElReader, ElChainContractManager};

#[async_trait]
pub trait ElWriter: Send + Sync {
    async fn register_as_operator(
        &self,
        operator: Operator,
    ) -> Result<TransactionReceipt, AvsError>;
    async fn update_operator_details(
        &self,
        operator: Operator,
    ) -> Result<TransactionReceipt, AvsError>;
    async fn deposit_erc20_into_strategy(
        &self,
        strategy_addr: Address,
        amount: U256,
    ) -> Result<TransactionReceipt, AvsError>;
}

#[async_trait]
impl<T: Config> ElWriter for ElChainContractManager<T> {
    async fn register_as_operator(
        &self,
        operator: Operator,
    ) -> Result<TransactionReceipt, AvsError> {
        log::info!("registering operator {} to EigenLayer", operator.address);

        let op_details = DelegationManager::OperatorDetails {
            earningsReceiver: operator.earnings_receiver_address,
            stakerOptOutWindowBlocks: operator.staker_opt_out_window_blocks,
            delegationApprover: operator.delegation_approver_address,
        };

        let delegation_manager =
            DelegationManager::new(self.delegation_manager_addr, self.eth_client_http.clone());
        let receipt = delegation_manager
            .registerAsOperator(op_details, operator.metadata_url)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!(
            "Successfully registered operator to EigenLayer, txHash: {}",
            receipt.transaction_hash
        );

        Ok(receipt)
    }

    async fn update_operator_details(
        &self,
        operator: Operator,
    ) -> Result<TransactionReceipt, AvsError> {
        log::info!(
            "updating operator details of operator {} to EigenLayer",
            operator.address
        );

        let op_details = DelegationManager::OperatorDetails {
            earningsReceiver: operator.earnings_receiver_address,
            stakerOptOutWindowBlocks: operator.staker_opt_out_window_blocks,
            delegationApprover: operator.delegation_approver_address,
        };

        let delegation_manager =
            DelegationManager::new(self.delegation_manager_addr, self.eth_client_http.clone());
        let receipt = delegation_manager
            .modifyOperatorDetails(op_details)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!(
            "successfully updated operator metadata URI, txHash: {}",
            receipt.transaction_hash
        );

        let receipt = delegation_manager
            .updateOperatorMetadataURI(operator.metadata_url)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!(
            "successfully updated operator details, txHash: {}",
            receipt.transaction_hash
        );

        Ok(receipt)
    }

    async fn deposit_erc20_into_strategy(
        &self,
        strategy_addr: Address,
        amount: U256,
    ) -> Result<TransactionReceipt, AvsError> {
        log::info!(
            "depositing {} tokens into strategy {}",
            amount,
            strategy_addr
        );

        let (_, underlying_token_contract, underlying_token_addr) = self
            .get_strategy_and_underlying_erc20_token(strategy_addr)
            .await?;
        let receipt = underlying_token_contract
            .approve(self.strategy_manager_addr, amount)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!(
            "approved {} tokens for deposit into strategy {} with txHash: {}",
            amount,
            strategy_addr,
            receipt.transaction_hash
        );

        let strategy_manager =
            StrategyManager::new(self.strategy_manager_addr, self.eth_client_http.clone());
        let receipt = strategy_manager
            .depositIntoStrategy(strategy_addr, underlying_token_addr, amount)
            .send()
            .await?
            .get_receipt()
            .await?;

        log::info!("deposited {} into strategy {}", amount, strategy_addr);

        Ok(receipt)
    }
}
