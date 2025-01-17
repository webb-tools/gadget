use alloy_primitives::Address;
use blueprint_examples::{eigen_context, periodic_web_poller, raw_tangle_events, services_context};
use gadget_sdk::info;
use gadget_sdk::runners::eigenlayer::EigenlayerBLSConfig;
use gadget_sdk::runners::{tangle::TangleConfig, BlueprintRunner};
use std::env;

#[gadget_sdk::main(env)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("~~~ Executing Blueprint Examples ~~~");

    // Read the EXAMPLE_PROTOCOL environment variable
    let example_protocol = env::var("EXAMPLE_PROTOCOL")
        .unwrap_or_else(|_| "tangle".to_string())
        .to_lowercase();

    match example_protocol.as_str() {
        "tangle" => {
            info!("Running Tangle examples");
            BlueprintRunner::new(TangleConfig::default(), env.clone())
                .job(raw_tangle_events::constructor(env.clone()).await?)
                .job(periodic_web_poller::constructor())
                .job(services_context::constructor(env.clone()).await?)
                .run()
                .await?;
        }
        "eigenlayer" => {
            info!("Running Eigenlayer examples");
            BlueprintRunner::new(
                EigenlayerBLSConfig::new(Address::default(), Address::default()),
                env.clone(),
            )
            .job(eigen_context::constructor(env.clone()).await?)
            .run()
            .await?;
        }
        _ => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid EXAMPLE_PROTOCOL value. Use 'tangle' or 'eigenlayer'.",
            )));
        }
    }

    info!("Exiting...");
    Ok(())
}
