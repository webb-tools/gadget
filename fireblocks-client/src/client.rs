use crate::types::*;
use alloy_primitives::Address;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::{Client as HttpClient, Url};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone)]
pub struct EncodingKeyWrapper {
    key: EncodingKey,
}

impl Debug for EncodingKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodingKeyWrapper").finish()
    }
}

#[derive(Debug, Clone)]
pub struct FireblocksClient {
    api_key: String,
    private_key: EncodingKeyWrapper,
    base_url: String,
    timeout: Duration,
    client: HttpClient,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
    pub code: i32,
}

impl FireblocksClient {
    pub fn new(
        api_key: String,
        private_key_pem: &[u8],
        base_url: String,
        timeout: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = EncodingKeyWrapper {
            key: EncodingKey::from_rsa_pem(private_key_pem).unwrap(),
        };
        let client = HttpClient::builder().timeout(timeout).build()?;

        Ok(FireblocksClient {
            api_key,
            private_key,
            base_url,
            timeout,
            client,
        })
    }

    fn sign_jwt(
        &self,
        path: &str,
        body: &impl Serialize,
        duration_seconds: i64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let expiration = now + duration_seconds;

        let body_bytes = serde_json::to_vec(body)?;
        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        let hashed = hasher.finalize();

        let claims = HashMap::from([
            ("uri".to_string(), path.to_string()),
            ("nonce".to_string(), nonce),
            ("iat".to_string(), now.to_string()),
            ("exp".to_string(), expiration.to_string()),
            ("sub".to_string(), self.api_key.clone()),
            ("bodyHash".to_string(), hex::encode(hashed)),
        ]);

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &self.private_key.key)?;
        Ok(token)
    }

    async fn make_request(
        &self,
        method: &str,
        path: &str,
        body: Option<impl Serialize>,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.sign_jwt(path, &body, self.timeout.as_secs() as i64)?;

        let client = &self.client;
        let request = client
            .request(method.parse()?, &url)
            .bearer_auth(token)
            .header("X-API-KEY", &self.api_key);

        let request = if let Some(body) = body {
            request.json(&body)
        } else {
            request
        };

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_response: ErrorResponse = response.json().await?;
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Error response ({}) from Fireblocks with code {}: {}",
                    status, error_response.code, error_response.message
                ),
            )));
        }

        Ok(response)
    }

    pub async fn contract_call(
        &self,
        call: ContractCallRequest,
    ) -> Result<TransactionResponse, Box<dyn Error>> {
        let req = TransactionRequest {
            operation: TransactionOperation::ContractCall,
            external_tx_id: call.external_tx_id,
            asset_id: call.asset_id,
            source: Address::from_slice(&hex::decode(call.source).unwrap()[..]),
            destination: Address::from_slice(&hex::decode(call.destination).unwrap()[..]),
            amount: call.amount,
            extra_parameters: ExtraParameters {
                calldata: call.calldata,
            },
            replace_tx_by_hash: call.replace_tx_by_hash,
            gas_price: call.gas_price,
            gas_limit: call.gas_limit,
            max_fee: call.max_fee,
            priority_fee: call.priority_fee,
            fee_level: call.fee_level,
        };
        log::debug!("Fireblocks call contract, req: {:?}", req);
        let res = self
            .make_request("POST", "/v1/transactions", Some(&req))
            .await?;
        let response = res.json::<TransactionResponse>().await?;

        Ok(TransactionResponse {
            id: response.id,
            status: response.status,
        })
    }

    pub async fn transfer(
        &self,
        body: &TransferRequest,
    ) -> Result<TransactionResponse, Box<dyn std::error::Error>> {
        let _req = TransactionRequest {
            operation: TransactionOperation::Transfer,
            external_tx_id: body.external_tx_id.clone().unwrap_or_default(),
            asset_id: body.asset_id.clone(),
            source: Address::from_slice(&hex::decode(&body.source).unwrap()[..]),
            destination: Address::from_slice(&hex::decode(&body.destination).unwrap()[..]),
            amount: body.amount.clone(),
            extra_parameters: ExtraParameters {
                calldata: "".to_string(),
            },
            replace_tx_by_hash: body.replace_tx_by_hash.clone().unwrap_or_default(),
            gas_price: body.gas_price.clone(),
            gas_limit: body.gas_limit.clone().unwrap_or_default(),
            max_fee: body.max_fee.clone(),
            priority_fee: body.priority_fee.clone(),
            fee_level: body.fee_level.clone(),
        };

        let response = self
            .make_request("POST", "/v1/transactions", Some(body))
            .await?;
        let transaction_response = response.json::<TransactionResponse>().await?;
        Ok(transaction_response)
    }

    pub async fn cancel_transaction(&self, tx_id: &str) -> Result<bool, Box<dyn Error>> {
        log::debug!("Fireblocks cancel transaction, txID: {}", tx_id);
        let path = format!("/v1/transactions/{}/cancel", tx_id);
        let response = self.make_request("POST", &path, None::<()>).await?;
        let cancel_response: CancelTransactionResponse = response.json().await?;
        Ok(cancel_response.success)
    }

    pub async fn list_contracts(
        &self,
    ) -> Result<Vec<WhitelistedContract>, Box<dyn std::error::Error>> {
        log::debug!("Fireblocks list contracts");
        let response = self
            .make_request("GET", "/v1/contracts", None::<()>)
            .await?;
        let contracts = response.json::<Vec<WhitelistedContract>>().await?;
        Ok(contracts)
    }

    pub async fn list_external_wallets(&self) -> Result<Vec<WhitelistedAccount>, Box<dyn Error>> {
        log::debug!("Fireblocks list external wallets");
        let res = self
            .make_request("GET", "/v1/external_wallets", None::<&()>)
            .await?
            .bytes()
            .await?;
        let accounts: Vec<WhitelistedAccount> = serde_json::from_slice(&res)?;
        Ok(accounts)
    }

    pub async fn list_vault_accounts(&self) -> Result<Vec<VaultAccount>, Box<dyn Error>> {
        log::debug!("Fireblocks list vault accounts");
        let mut accounts = Vec::new();
        let mut p = Paging {
            before: None,
            after: None,
        };
        let mut next = true;

        while next {
            let mut u = Url::parse("/v1/vault/accounts_paged")?;
            let mut q = u.query_pairs_mut();
            if let Some(before) = &p.before {
                q.append_pair("before", before);
            }
            if let Some(after) = &p.after {
                q.append_pair("after", after);
            }
            drop(q); // Drop the query pairs mutable reference

            let url = u.to_string();
            let res = self
                .make_request("GET", &url, None::<&()>)
                .await?
                .bytes()
                .await?;

            let response: ListVaultAccountsResponse = serde_json::from_slice(&res)?;
            accounts.extend(response.accounts);
            p = response.paging;

            if p.after.is_none() {
                next = false;
            }
        }

        Ok(accounts)
    }

    pub async fn get_transaction(&self, tx_id: &str) -> Result<Transaction, Box<dyn Error>> {
        log::debug!("Fireblocks get transaction {}", tx_id);

        let path = format!("/v1/transactions/{}", tx_id);
        let res = self
            .make_request("GET", &path, None::<&()>)
            .await?
            .bytes()
            .await?;

        let tx: Transaction = serde_json::from_slice(&res)?;

        Ok(tx)
    }

    pub async fn get_asset_addresses(
        &self,
        vault_id: &str,
        asset_id: &AssetID,
    ) -> Result<Vec<AssetAddress>, Box<dyn Error>> {
        log::debug!("Fireblocks get asset addresses {} {}", vault_id, asset_id);

        let path = format!(
            "/v1/vault/accounts/{}/assets/{}/addresses",
            vault_id, asset_id
        );
        let res = self
            .make_request("GET", &path, None::<&()>)
            .await?
            .bytes()
            .await?;

        let addresses: Vec<AssetAddress> = serde_json::from_slice(&res)?;

        Ok(addresses)
    }
}

#[derive(Deserialize)]
struct CancelTransactionResponse {
    success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetID {
    ETH,
    GoerliETH,
    HolETH,
}

impl AssetID {
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(AssetID::ETH),
            5 => Some(AssetID::GoerliETH),
            17000 => Some(AssetID::HolETH),
            _ => None,
        }
    }
}

impl Display for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AssetID::ETH => write!(f, "ETH"),
            AssetID::GoerliETH => write!(f, "GOERLI_ETH"),
            AssetID::HolETH => write!(f, "HOL_ETH"),
        }
    }
}

impl From<&str> for AssetID {
    fn from(s: &str) -> Self {
        match s {
            "ETH" => AssetID::ETH,
            "GOERLI_ETH" => AssetID::GoerliETH,
            "HOL_ETH" => AssetID::HolETH,
            _ => panic!("Invalid asset ID"),
        }
    }
}
