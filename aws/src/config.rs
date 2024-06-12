use aws_config::meta::region::RegionProviderChain;

use aws_config::retry::RetryConfig;
use aws_config::Region;

use aws_sdk_s3::config::Credentials;

use aws_types::SdkConfig;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::OnceCell;

static SDK_CONFIG: OnceCell<Arc<SdkConfig>> = OnceCell::const_new();

// Example usage:
//
// let aws_config = get_aws_config(
//     "access_key",
//     "secret_access_key",
//     "us-west-2",
//     Some("http://localhost:9000"),
// )
// .await?;
// let _client = Client::new(&aws_config);
async fn get_aws_config(
    access_key: &str,
    secret_access_key: &str,
    region: &str,
    endpoint_url: Option<&str>,
) -> Result<Arc<SdkConfig>, Box<dyn Error>> {
    let credentials = Credentials::new(access_key, secret_access_key, None, None, "static");

    let region_provider =
        RegionProviderChain::default_provider().or_else(Region::new(region.to_string()));

    let shared_config = aws_config::from_env()
        .region(region_provider)
        .credentials_provider(credentials)
        .endpoint_url(endpoint_url.unwrap_or_default())
        .retry_config(RetryConfig::standard().with_max_attempts(2))
        .load()
        .await;

    let sdk_config = Arc::new(shared_config);
    Ok(sdk_config)
}
