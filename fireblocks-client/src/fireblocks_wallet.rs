use alloy_network::Network;
use alloy_primitives::{Address, B256, U256};
use alloy_provider::Provider;
use alloy_transport::Transport;

use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

use crate::*;

#[derive(Debug, Error)]
pub enum FireblocksError {
    #[error("transaction not yet broadcasted")]
    NotYetBroadcasted,
    #[error("transaction receipt not yet available")]
    ReceiptNotYetAvailable,
    #[error("transaction failed")]
    TransactionFailed,
    #[error("unsupported chain {0}")]
    UnsupportedChain(u64),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("error sending a transaction {0}: {1}")]
    SendRequestError(String, String),
    #[error("transaction has no value and no data")]
    NoValueNoData,
    #[error("account {0} not found in whitelisted accounts")]
    WhitelistedAccountNotFound(String),
    #[error("contract {0} not found in whitelisted contracts")]
    WhitelistedContractNotFound(String),
}

pub struct FireblocksWallet<T, P, N>
where
    T: Transport + Clone,
    P: Provider<T, N> + Copy + 'static,
    N: Network,
{
    fireblocks_client: Arc<FireblocksClient>,
    eth_client: P,
    vault_account_name: String,
    chain_id: u64,
    nonce_to_tx_id: AsyncMutex<HashMap<u64, String>>,
    tx_id_to_nonce: AsyncMutex<HashMap<String, u64>>,
    account: AsyncMutex<Option<VaultAccount>>,
    whitelisted_contracts: AsyncMutex<HashMap<Address, WhitelistedContract>>,
    whitelisted_accounts: AsyncMutex<HashMap<Address, WhitelistedAccount>>,
    phantom: std::marker::PhantomData<(T, N)>,
}

impl<T, P, N> FireblocksWallet<T, P, N>
where
    T: Transport + Clone,
    P: Provider<T, N> + Copy + 'static,
    N: Network,
{
    pub async fn new(
        fireblocks_client: Arc<FireblocksClient>,
        eth_client: P,
        vault_account_name: String,
    ) -> Result<Self, FireblocksError> {
        let chain_id = eth_client.get_chain_id().await.unwrap_or(1u64);
        log::debug!("Creating new Fireblocks wallet for chain {chain_id}");
        Ok(Self {
            fireblocks_client,
            eth_client,
            vault_account_name,
            chain_id,
            nonce_to_tx_id: AsyncMutex::new(HashMap::new()),
            tx_id_to_nonce: AsyncMutex::new(HashMap::new()),
            account: AsyncMutex::new(None),
            whitelisted_contracts: AsyncMutex::new(HashMap::new()),
            whitelisted_accounts: AsyncMutex::new(HashMap::new()),
            phantom: std::marker::PhantomData,
        })
    }

    async fn get_account(&self) -> Result<VaultAccount, FireblocksError> {
        let mut account = self.account.lock().await;
        if account.is_none() {
            let accounts = self
                .fireblocks_client
                .list_vault_accounts()
                .await
                .map_err(|e| {
                    FireblocksError::SendRequestError(
                        "list_vault_accounts".to_string(),
                        e.to_string(),
                    )
                })?;
            for a in accounts {
                if a.name == self.vault_account_name {
                    *account = Some(a);
                    break;
                }
            }
        }
        account.clone().ok_or_else(|| {
            FireblocksError::WhitelistedAccountNotFound(self.vault_account_name.clone())
        })
    }

    async fn get_whitelisted_account(
        &self,
        address: Address,
    ) -> Result<WhitelistedAccount, FireblocksError> {
        let asset_id = AssetID::from_chain_id(self.chain_id)
            .ok_or(FireblocksError::UnsupportedChain(self.chain_id))?;
        let mut whitelisted_accounts = self.whitelisted_accounts.lock().await;
        if let Some(account) = whitelisted_accounts.get(&address) {
            return Ok(account.clone());
        }
        let accounts = self
            .fireblocks_client
            .list_external_wallets()
            .await
            .map_err(|e| {
                FireblocksError::SendRequestError(
                    "list_external_wallets".to_string(),
                    e.to_string(),
                )
            })?;
        for account in accounts {
            for asset in &account.assets {
                if asset.address == address && asset.status == "APPROVED" && asset.id == asset_id {
                    whitelisted_accounts.insert(address, account.clone());
                    return Ok(account);
                }
            }
        }
        Err(FireblocksError::WhitelistedAccountNotFound(
            address.to_string(),
        ))
    }

    async fn get_whitelisted_contract(
        &self,
        address: Address,
    ) -> Result<WhitelistedContract, FireblocksError> {
        let asset_id = AssetID::from_chain_id(self.chain_id)
            .ok_or(FireblocksError::UnsupportedChain(self.chain_id))?;
        let mut whitelisted_contracts = self.whitelisted_contracts.lock().await;
        if let Some(contract) = whitelisted_contracts.get(&address) {
            return Ok(contract.clone());
        }
        let contracts = self.fireblocks_client.list_contracts().await.map_err(|e| {
            FireblocksError::SendRequestError("list_contracts".to_string(), e.to_string())
        })?;
        for contract in contracts {
            for asset in &contract.assets {
                if asset.address == address && asset.status == "APPROVED" && asset.id == asset_id {
                    whitelisted_contracts.insert(address, contract.clone());
                    return Ok(contract);
                }
            }
        }
        Err(FireblocksError::WhitelistedContractNotFound(
            address.to_string(),
        ))
    }

    pub async fn send_transaction(
        &self,
        tx: &alloy_rpc_types::TransactionRequest,
    ) -> Result<String, FireblocksError> {
        let asset_id = AssetID::from_chain_id(self.chain_id)
            .ok_or(FireblocksError::UnsupportedChain(self.chain_id))?;
        let account = self.get_account().await?;
        if !account
            .assets
            .iter()
            .any(|a| a.id == asset_id && a.available != "0")
        {
            return Err(FireblocksError::InsufficientFunds);
        }

        let mut nonce_to_tx_id = self.nonce_to_tx_id.lock().await;
        let mut tx_id_to_nonce = self.tx_id_to_nonce.lock().await;

        let nonce = tx.nonce.ok_or(FireblocksError::NoValueNoData)?;
        let replace_tx_by_hash = if let Some(tx_id) = nonce_to_tx_id.get(&nonce) {
            let fireblock_tx = self
                .fireblocks_client
                .get_transaction(tx_id)
                .await
                .map_err(|e| {
                    FireblocksError::SendRequestError("get_transaction".to_string(), e.to_string())
                })?;
            fireblock_tx.tx_hash
        } else {
            "".to_string()
        };

        let _gas_limit = tx.gas;
        let (max_fee, priority_fee, gas_price, fee_level) =
            if tx.max_fee_per_gas.is_some() && tx.max_priority_fee_per_gas.is_some() {
                (
                    wei_to_gwei(U256::from(tx.max_fee_per_gas.unwrap())).to_string(),
                    wei_to_gwei(U256::from(tx.max_priority_fee_per_gas.unwrap())).to_string(),
                    "".to_string(),
                    None,
                )
            } else if tx.gas_price.is_some() {
                (
                    "".to_string(),
                    "".to_string(),
                    wei_to_gwei(U256::from(tx.gas_price.unwrap())).to_string(),
                    None,
                )
            } else {
                (
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    Some(FeeLevel::High),
                )
            };

        let res = if tx.input.input.is_none() && tx.value.unwrap_or_default() > U256::from(0) {
            let target_account = self
                .get_whitelisted_account(*tx.to.unwrap().to().unwrap())
                .await?;
            let req = TransferRequest {
                external_tx_id: Some("".to_string()),
                asset_id: asset_id.to_string(),
                source: account.id.clone(),
                destination: target_account.id.clone(),
                amount: wei_to_ether(tx.value.unwrap()).to_string(),
                replace_tx_by_hash: Some(replace_tx_by_hash),
                gas_price: Some(gas_price),
                gas_limit: tx.gas.map(|g| g.to_string()),
                max_fee: Some(max_fee),
                priority_fee: Some(priority_fee),
                fee_level,
            };
            self.fireblocks_client.transfer(&req).await.map_err(|e| {
                FireblocksError::SendRequestError("transfer".to_string(), e.to_string())
            })?
        } else if tx.input.input.is_some() {
            let contract = self
                .get_whitelisted_contract(*tx.to.unwrap().to().unwrap())
                .await?;
            let req = ContractCallRequest {
                external_tx_id: "".to_string(),
                asset_id: asset_id.to_string(),
                source: account.id.clone(),
                destination: contract.id.clone(),
                amount: wei_to_ether(tx.value.unwrap()).to_string(),
                calldata: hex::encode(tx.input.input.as_ref().unwrap()),
                replace_tx_by_hash,
                gas_price: Some(gas_price),
                gas_limit: tx.gas.map(|g| g.to_string()).unwrap_or_default(),
                max_fee: Some(max_fee),
                priority_fee: Some(priority_fee),
                fee_level,
            };
            self.fireblocks_client
                .contract_call(req)
                .await
                .map_err(|e| {
                    FireblocksError::SendRequestError("contract_call".to_string(), e.to_string())
                })?
        } else {
            return Err(FireblocksError::NoValueNoData);
        };

        nonce_to_tx_id.insert(nonce, res.id.clone());
        tx_id_to_nonce.insert(res.id.clone(), nonce);
        log::debug!(
            "Fireblocks contract call complete {} {}",
            res.id,
            res.status
        );

        Ok(res.id)
    }

    pub async fn cancel_transaction_broadcast(
        &self,
        tx_id: String,
    ) -> Result<bool, FireblocksError> {
        self.fireblocks_client
            .cancel_transaction(&tx_id)
            .await
            .map_err(|e| {
                FireblocksError::SendRequestError("cancel_transaction".to_string(), e.to_string())
            })
    }

    pub async fn get_transaction_receipt(
        &self,
        tx_id: String,
    ) -> Result<<N as Network>::ReceiptResponse, FireblocksError> {
        let fireblock_tx = self
            .fireblocks_client
            .get_transaction(&tx_id)
            .await
            .map_err(|e| {
                FireblocksError::SendRequestError("get_transaction".to_string(), e.to_string())
            })?;
        if fireblock_tx.status == TxStatus::Completed {
            let tx_hash = B256::from_slice(&hex::decode(fireblock_tx.tx_hash).unwrap());
            let receipt = self
                .eth_client
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|e| {
                    if e.to_string().contains("not found") {
                        FireblocksError::ReceiptNotYetAvailable
                    } else {
                        FireblocksError::TransactionFailed
                    }
                })?;
            let mut nonce_to_tx_id = self.nonce_to_tx_id.lock().await;
            let mut tx_id_to_nonce = self.tx_id_to_nonce.lock().await;
            if let Some(nonce) = tx_id_to_nonce.get(&tx_id) {
                nonce_to_tx_id.remove(nonce);
                tx_id_to_nonce.remove(&tx_id);
            }

            if let Some(r) = receipt {
                return Ok(r);
            } else {
                return Err(FireblocksError::ReceiptNotYetAvailable);
            }
        }
        if matches!(
            fireblock_tx.status,
            TxStatus::Failed | TxStatus::Rejected | TxStatus::Cancelled | TxStatus::Blocked
        ) {
            return Err(FireblocksError::TransactionFailed);
        }
        Err(FireblocksError::NotYetBroadcasted)
    }

    pub async fn sender_address(&self) -> Result<Address, FireblocksError> {
        let account = self.get_account().await?;
        let addresses = self
            .fireblocks_client
            .get_asset_addresses(&account.id, &AssetID::from_chain_id(self.chain_id).unwrap())
            .await
            .map_err(|e| {
                FireblocksError::SendRequestError("get_asset_addresses".to_string(), e.to_string())
            })?;
        if addresses.is_empty() {
            return Err(FireblocksError::NoValueNoData);
        }
        Ok(addresses[0].address.parse().unwrap())
    }
}

fn wei_to_gwei(wei: U256) -> U256 {
    wei / U256::pow(U256::from(9), U256::from(10))
}

fn wei_to_ether(wei: U256) -> U256 {
    wei / U256::pow(U256::from(18), U256::from(10))
}
