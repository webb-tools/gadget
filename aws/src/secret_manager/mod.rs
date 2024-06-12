use aws_config::{meta::region::RegionProviderChain, BehaviorVersion, Region};
use aws_sdk_secretsmanager::{operation::get_secret_value::GetSecretValueOutput, Client};
use std::error::Error as StdError;

async fn read_string_from_secret_manager(
    secret_name: &str,
    region: &str,
) -> Result<String, Box<dyn StdError>> {
    let region_provider =
        RegionProviderChain::default_provider().or_else(Region::new(region.to_string()));

    let config = aws_config::load_defaults(BehaviorVersion::latest())
        .await
        .into_builder()
        .region(region_provider.region().await)
        .build();

    // Create Secrets Manager client
    let client = Client::new(&config);

    let result: GetSecretValueOutput = client
        .get_secret_value()
        .secret_id(secret_name)
        .version_stage("AWSCURRENT")
        .send()
        .await?;

    // Decrypts secret using the associated KMS key.
    if let Some(secret_string) = result.secret_string() {
        Ok(secret_string.to_string())
    } else {
        Err("Secret string not found".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_read_string() {
        // Skip this test as it's meant for manual runs only
        if std::env::var("RUN_MANUAL_TESTS").is_err() {
            println!("Skipping manual test");
            return;
        }

        let secret_name = "SECRET_NAME";
        let region = "REGION";

        let rt = Runtime::new().unwrap();
        let result =
            rt.block_on(async { read_string_from_secret_manager(secret_name, region).await });

        match result {
            Ok(value) => println!("Secret value: {}", value),
            Err(err) => panic!("Failed to read secret: {}", err),
        }
    }
}
