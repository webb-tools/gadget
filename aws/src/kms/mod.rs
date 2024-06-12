use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::Region;

use aws_sdk_kms::Client;
use std::error::Error;

pub mod get_public_key;
pub mod get_signature;
pub mod signer;

async fn new_kms_client(region: &str) -> Result<Client, Box<dyn Error>> {
    let region_provider =
        RegionProviderChain::default_provider().or_else(Region::new(region.to_string()));

    let config = aws_config::load_defaults(BehaviorVersion::latest())
        .await
        .into_builder()
        .region(region_provider.region().await)
        .build();
    let client = Client::new(&config);

    Ok(client)
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_sdk_kms::types::{KeySpec, KeyUsageType};
    use get_public_key::get_ecdsa_public_key;
    use get_signature::get_ecdsa_signature;

    struct TestContext {
        kms_client: Client,
        key_id: String,
    }

    impl TestContext {
        async fn setup() -> Self {
            let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
            let kms_client = Client::new(&config);

            // Create a new KMS key
            let key = kms_client
                .create_key()
                .key_usage(KeyUsageType::SignVerify)
                .key_spec(KeySpec::EccSecgP256K1)
                .send()
                .await
                .expect("Failed to create KMS key");

            let key_id = key.key_metadata.unwrap().key_id;

            TestContext { kms_client, key_id }
        }

        async fn teardown(&self) {
            self.kms_client
                .schedule_key_deletion()
                .key_id(&self.key_id)
                .send()
                .await
                .expect("Failed to schedule key deletion");
        }
    }

    #[tokio::test]
    async fn test_get_public_key() {
        let context = TestContext::setup().await;
        let pk = get_ecdsa_public_key(&context.kms_client, &context.key_id)
            .await
            .expect("Failed to get public key");
        println!("Public key: {:?}", pk);
        context.teardown().await;
    }

    use aws_config::meta::region::RegionProviderChain;

    #[tokio::test]
    async fn test_get_ecdsa_signature() {
        let region_provider = RegionProviderChain::default_provider().or_else("us-west-2");
        let config = aws_config::from_env().region(region_provider).load().await;
        let client = Client::new(&config);

        let key_id = "your-key-id";
        let message = b"your-message";

        let (r, s) = get_ecdsa_signature(&client, key_id, message)
            .await
            .expect("Failed to get ECDSA signature");

        println!("R: {:?}", r);
        println!("S: {:?}", s);

        assert!(!r.is_empty(), "R should not be empty");
        assert!(!s.is_empty(), "S should not be empty");
    }
}
