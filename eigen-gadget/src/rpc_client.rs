use eigen_utils::types::AvsError;
use reqwest::{Client, Response, Url};
use serde_json;
use std::time::Duration;
use tokio::time::sleep;

use crate::avs::SignedTaskResponse;

#[derive(Clone)]
pub struct AggregatorRpcClient {
    client: Client,
    // metrics: Metrics,
    aggregator_ip_port_addr: String,
}

impl AggregatorRpcClient {
    pub fn new(
        aggregator_ip_port_addr: String,
        // metrics: Metrics
    ) -> Self {
        AggregatorRpcClient {
            client: Client::new(),
            // metrics,
            aggregator_ip_port_addr,
        }
    }

    async fn dial_aggregator_rpc_client(&self) -> Result<(), Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(&format!("http://{}/", self.aggregator_ip_port_addr))
            .send()
            .await?;
        log::info!("Dialing aggregator RPC client. Response: {:?}", response);
        Ok(())
    }

    pub async fn send_signed_task_response_to_aggregator(
        &self,
        signed_task_response: SignedTaskResponse,
    ) {
        log::info!("RPC client is nil. Dialing aggregator RPC client");
        if let Err(err) = self.dial_aggregator_rpc_client().await {
            log::error!("Could not dial aggregator RPC client. Not sending signed task response header to aggregator. Is aggregator running? Error: {:?}", err);
            return;
        }

        for _ in 0..5 {
            let response = self
                .call_aggregator_rpc(
                    "Aggregator.ProcessSignedTaskResponse",
                    &signed_task_response,
                )
                .await;

            match response {
                Ok(res) => {
                    log::info!(
                        "Signed task response header accepted by aggregator. Reply: {:?}",
                        res
                    );
                    // self.metrics.inc_num_tasks_accepted_by_aggregator();
                    return;
                }
                Err(err) => {
                    log::error!("Received error from aggregator: {:?}", err);
                }
            }
            log::info!("Retrying in 2 seconds");
            sleep(Duration::from_secs(2)).await;
        }
        log::error!("Could not send signed task response to aggregator. Tried 5 times.");
    }

    async fn call_aggregator_rpc(
        &self,
        method: &str,
        params: &SignedTaskResponse,
    ) -> Result<Response, AvsError> {
        let url: Url = format!("http://{}/{}", self.aggregator_ip_port_addr, method)
            .parse()
            .unwrap();

        let json = serde_json::to_string(params).map_err(AvsError::from)?;

        reqwest::Client::new()
            .post(url)
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await
            .map_err(AvsError::from)
    }
}
