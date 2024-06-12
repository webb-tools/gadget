use std::fmt::Display;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::AssetID;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtraParameters {
    pub calldata: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum TransactionOperation {
    #[serde(rename = "CONTRACT_CALL")]
    ContractCall,
    #[serde(rename = "TRANSFER")]
    Transfer,
    #[serde(rename = "MINT")]
    Mint,
    #[serde(rename = "BURN")]
    Burn,
    #[serde(rename = "TYPED_MESSAGE")]
    TypedMessage,
    #[serde(rename = "RAW")]
    Raw,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum FeeLevel {
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct TransferRequest {
    pub external_tx_id: Option<String>,
    pub asset_id: String,
    pub source: String,
    pub destination: String,
    pub amount: String,
    pub replace_tx_by_hash: Option<String>,
    pub gas_price: Option<String>,
    pub gas_limit: Option<String>,
    pub max_fee: Option<String>,
    pub priority_fee: Option<String>,
    pub fee_level: Option<FeeLevel>,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ContractCallRequest {
    pub external_tx_id: String,
    pub asset_id: String,
    pub source: String,
    pub destination: String,
    pub amount: String,
    pub replace_tx_by_hash: String,
    pub gas_price: Option<String>,
    pub gas_limit: String,
    pub max_fee: Option<String>,
    pub priority_fee: Option<String>,
    pub fee_level: Option<FeeLevel>,
    pub calldata: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub operation: TransactionOperation,
    pub external_tx_id: String,
    pub asset_id: String,
    pub source: Address,
    pub destination: Address,
    pub amount: String,
    pub extra_parameters: ExtraParameters,
    pub replace_tx_by_hash: String,
    pub gas_price: Option<String>,
    pub gas_limit: String,
    pub max_fee: Option<String>,
    pub priority_fee: Option<String>,
    pub fee_level: Option<FeeLevel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub id: String,
    pub status: TxStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetAddress {
    pub asset_id: String,
    pub address: String,
    pub tag: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub address_type: Option<String>,
    pub legacy_address: Option<String>,
    pub enterprise_address: Option<String>,
    pub user_defined: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AmountInfo {
    pub amount: String,
    pub requested_amount: String,
    pub net_amount: String,
    pub amount_usd: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeeInfo {
    pub network_fee: String,
    pub service_fee: String,
    pub gas_price: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockInfo {
    pub block_height: String,
    pub block_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub external_id: String,
    pub status: TxStatus,
    pub sub_status: String,
    pub tx_hash: String,
    pub operation: String,
    pub created_at: i64,
    pub last_updated: i64,
    pub asset_id: String,
    pub source: Address,
    pub source_address: String,
    pub destination: Address,
    pub destination_address: String,
    pub destination_address_description: String,
    pub destination_tag: String,
    pub amount_info: AmountInfo,
    pub fee_info: FeeInfo,
    pub fee_currency: String,
    pub extra_parameters: ExtraParameters,
    pub num_of_confirmations: i32,
    pub block_info: BlockInfo,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Asset {
    pub id: AssetID,
    pub status: String,
    pub address: Address,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAsset {
    pub id: AssetID,
    pub total: String,
    pub balance: String,
    pub available: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WhitelistedContract {
    pub id: String,
    pub name: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistedAccount {
    pub id: String,
    pub name: String,
    pub assets: Vec<Asset>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum TxStatus {
    Submitted,
    PendingScreening,
    PendingAuthorization,
    Queued,
    PendingSignature,
    PendingEmailApproval,
    Pending3rdParty,
    Broadcasting,
    Confirming,
    Completed,
    Cancelling,
    Cancelled,
    Blocked,
    Rejected,
    Failed,
}

impl TxStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxStatus::Submitted => "SUBMITTED",
            TxStatus::PendingScreening => "PENDING_AML_SCREENING",
            TxStatus::PendingAuthorization => "PENDING_AUTHORIZATION",
            TxStatus::Queued => "QUEUED",
            TxStatus::PendingSignature => "PENDING_SIGNATURE",
            TxStatus::PendingEmailApproval => "PENDING_3RD_PARTY_MANUAL_APPROVAL",
            TxStatus::Pending3rdParty => "PENDING_3RD_PARTY",
            TxStatus::Broadcasting => "BROADCASTING",
            TxStatus::Confirming => "CONFIRMING",
            TxStatus::Completed => "COMPLETED",
            TxStatus::Cancelling => "CANCELLING",
            TxStatus::Cancelled => "CANCELLED",
            TxStatus::Blocked => "BLOCKED",
            TxStatus::Rejected => "REJECTED",
            TxStatus::Failed => "FAILED",
        }
    }
}

impl Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultAccount {
    pub id: String,
    pub name: String,
    pub assets: Vec<VaultAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paging {
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListVaultAccountsResponse {
    pub accounts: Vec<VaultAccount>,
    pub paging: Paging,
}
