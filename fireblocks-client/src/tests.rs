use crate::*;
use alloy_primitives::Address;
use log::{debug, info};

use std::fs;
use std::sync::Arc;
use std::time::Duration;

const SANDBOX_API: &str = "https://sandbox-api.fireblocks.io";
const SECRET_KEY_PATH: &str = "FILL_ME_IN";
const API_KEY: &str = "FILL_ME_IN";

async fn new_fireblocks_client() -> Arc<FireblocksClient> {
    let secret_key = fs::read_to_string(SECRET_KEY_PATH).expect("Unable to read secret key");
    let client = FireblocksClient::new(
        API_KEY.to_string(),
        secret_key.as_bytes(),
        SANDBOX_API.to_string(),
        Duration::from_secs(5),
    )
    .unwrap();
    Arc::new(client)
}

#[tokio::test]
async fn test_list_contracts() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let contracts = client.list_contracts().await.unwrap();
    for contract in contracts {
        info!("Contract: {:?}", contract);
    }
}

#[tokio::test]
async fn test_contract_call() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let destination = "FILL_ME_IN";
    let idempotence_key = "FILL_ME_IN";
    let req = ContractCallRequest {
        external_tx_id: idempotence_key.to_string(),
        asset_id: "ETH_TEST6".to_string(),
        source: Address::from_slice(&hex::decode("2").unwrap()[..]).to_string(),
        destination: Address::from_slice(&hex::decode(destination).unwrap()[..]).to_string(),
        amount: "0".to_string(),
        calldata: "0x5140a548000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000030000000000000000000000002177dee1f66d6dbfbf517d9c4f316024c6a21aeb000000000000000000000000ad9770d6b5514724c7b766f087bea8a784038cbe000000000000000000000000cb14cfaac122e52024232583e7354589aede74ff00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000".to_string(),
        replace_tx_by_hash: "".to_string(),
        gas_price: None,
        gas_limit: "".to_string(),
        max_fee: None,
        priority_fee: None,
        fee_level: Some(FeeLevel::High),
    };
    let resp = client.contract_call(req).await.unwrap();
    info!("txID: {}, status: {:?}", resp.id, resp.status);
}

#[tokio::test]
async fn test_transfer() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let destination = "FILL_ME_IN";
    let req = TransferRequest {
        external_tx_id: None,
        asset_id: "ETH_TEST6".to_string(),
        source: "5".to_string(),
        destination: destination.to_string(),
        amount: "1".to_string(),
        replace_tx_by_hash: None,
        gas_price: None,
        gas_limit: None,
        max_fee: None,
        priority_fee: None,
        fee_level: Some(FeeLevel::High),
    };
    let resp = client.transfer(&req).await.unwrap();
    info!("txID: {}, status: {:?}", resp.id, resp.status);
}

#[tokio::test]
async fn test_cancel_transaction() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let tx_id = "FILL_ME_IN";
    let success = client.cancel_transaction(tx_id).await.unwrap();
    info!("txID: {}, success: {}", tx_id, success);
}

#[tokio::test]
async fn test_list_external_wallets() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let wallets = client.list_external_wallets().await.unwrap();
    for wallet in wallets {
        info!("Wallet: {:?}", wallet);
    }
}

#[tokio::test]
async fn test_list_vault_accounts() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let accounts = client.list_vault_accounts().await.unwrap();
    for account in accounts {
        info!("Account: {:?}", account);
    }
}

#[tokio::test]
async fn test_get_transaction() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let tx_id = "FILL_ME_IN";
    let tx = client.get_transaction(tx_id).await.unwrap();
    info!("Transaction: {:?}", tx);
}

#[tokio::test]
async fn test_get_asset_addresses() {
    let _ = pretty_env_logger::try_init();
    debug!("skipping test as it's meant for manual runs only");

    let client = new_fireblocks_client().await;
    let vault_id = "FILL_ME_IN";
    let _asset_id = "FILL_ME_IN";
    let chain_id: u64 = 1;
    let addresses = client
        .get_asset_addresses(vault_id, &AssetID::from_chain_id(chain_id).unwrap())
        .await
        .unwrap();
    for address in addresses {
        info!("Address: {:?}", address);
    }
}
