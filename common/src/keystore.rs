use crate::utils::{deserialize, serialize};
use crate::Error;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sp_core::ecdsa::Pair as EcdsaPair;
use sp_core::sr25519::Pair as Sr25519Pair;
use sp_core::{keccak_256, Pair};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Row, Sqlite};
use std::collections::HashMap;
use std::sync::Arc;

pub type ECDSAKeyStore<BE> = GenericKeyStore<BE, EcdsaPair>;
pub type Sr25519KeyStore<BE> = GenericKeyStore<BE, Sr25519Pair>;

#[derive(Clone)]
pub struct GenericKeyStore<BE: KeystoreBackend, P: Pair> {
    backend: BE,
    pair: P,
}

impl<P: Pair> GenericKeyStore<InMemoryBackend, P> {
    pub fn in_memory(pair: P) -> Self {
        GenericKeyStore {
            backend: InMemoryBackend::new(),
            pair,
        }
    }
}

impl<P: Pair> GenericKeyStore<SqliteBackend, P> {
    pub async fn sqlite_in_memory(pair: P) -> Result<Self, Box<dyn std::error::Error>> {
        let backend = SqliteBackend::in_memory().await?;
        Ok(GenericKeyStore { backend, pair })
    }
}

impl<P: Pair, Backend: KeystoreBackend> GenericKeyStore<Backend, P> {
    pub fn new(backend: Backend, pair: P) -> Self {
        GenericKeyStore { backend, pair }
    }
}

impl<P: Pair, BE: KeystoreBackend> GenericKeyStore<BE, P> {
    pub fn pair(&self) -> &P {
        &self.pair
    }
}

impl<P: Pair, BE: KeystoreBackend> GenericKeyStore<BE, P> {
    pub async fn get<T: DeserializeOwned>(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<T>, crate::Error> {
        self.backend.get(key).await
    }

    pub async fn get_job_result<T: DeserializeOwned>(
        &self,
        job_id: u64,
    ) -> Result<Option<T>, crate::Error> {
        let key = keccak_256(&job_id.to_be_bytes());
        self.get(&key).await
    }

    pub async fn set<T: Serialize + Send>(
        &self,
        key: &[u8; 32],
        value: T,
    ) -> Result<(), crate::Error> {
        self.backend.set(key, value).await
    }

    pub async fn set_job_result<T: Serialize + Send>(
        &self,
        job_id: u64,
        value: T,
    ) -> Result<(), crate::Error> {
        let key = keccak_256(&job_id.to_be_bytes());
        self.set(&key, value).await
    }
}

#[async_trait]
pub trait KeystoreBackend: Clone + Send + Sync + 'static {
    async fn get<T: DeserializeOwned>(&self, key: &[u8; 32]) -> Result<Option<T>, crate::Error>;
    async fn set<T: Serialize + Send>(&self, key: &[u8; 32], value: T) -> Result<(), crate::Error>;
}

#[derive(Clone)]
pub struct InMemoryBackend {
    map: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeystoreBackend for InMemoryBackend {
    async fn get<T: DeserializeOwned>(&self, key: &[u8; 32]) -> Result<Option<T>, crate::Error> {
        if let Some(bytes) = self.map.read().get(key).cloned() {
            let value: T = deserialize(&bytes).map_err(|rr| crate::Error::KeystoreError {
                err: format!("Failed to deserialize value: {:?}", rr),
            })?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn set<T: Serialize + Send>(&self, key: &[u8; 32], value: T) -> Result<(), crate::Error> {
        let serialized = serialize(&value).map_err(|rr| crate::Error::KeystoreError {
            err: format!("Failed to serialize value: {:?}", rr),
        })?;
        self.map.write().insert(*key, serialized);
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteBackend {
    pool: Pool<Sqlite>,
}

impl SqliteBackend {
    pub async fn in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new("sqlite://:memory:").await
    }

    // Initialize a new key-value store with a SqlitePool
    pub async fn new(database_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = SqlitePoolOptions::new().connect(database_url).await?;

        // Ensure the table exists
        sqlx::query(
            r"CREATE TABLE IF NOT EXISTS key_value_store (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
              )",
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl KeystoreBackend for SqliteBackend {
    async fn get<T: DeserializeOwned>(&self, key: &[u8; 32]) -> Result<Option<T>, Error> {
        let key = key_to_string(key);
        let result = sqlx::query("SELECT value FROM key_value_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| Error::KeystoreError {
                err: format!("Failed to fetch value: {:?}", err),
            })?;

        match result {
            Some(row) => {
                let value: Vec<u8> = row.get("value");
                let value: T = deserialize(&value).map_err(|rr| Error::KeystoreError {
                    err: format!("Failed to deserialize value: {:?}", rr),
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn set<T: Serialize + Send>(&self, key: &[u8; 32], value: T) -> Result<(), Error> {
        let key = key_to_string(key);
        let value = serialize(&value).map_err(|rr| Error::KeystoreError {
            err: format!("Failed to serialize value: {:?}", rr),
        })?;

        sqlx::query("INSERT INTO key_value_store (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await
            .map_err(|err| Error::KeystoreError {
                err: format!("Failed to insert value: {:?}", err),
            })?;
        Ok(())
    }
}

fn key_to_string(key: &[u8; 32]) -> String {
    hex::encode(key)
}

#[cfg(test)]
mod tests {
    use crate::prelude::KeystoreBackend;

    #[tokio::test]
    async fn test_in_memory_kv_store() {
        let store = super::SqliteBackend::in_memory().await.unwrap();
        let key = [0u8; 32];
        let value = "hello".to_string();
        store.set(&key, value.clone()).await.unwrap();
        let result: String = store.get(&key).await.unwrap().unwrap();
        assert_eq!(value, result);
    }
}
