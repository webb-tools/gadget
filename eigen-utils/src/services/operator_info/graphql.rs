use alloy_primitives::Address;
use alloy_provider::Provider;

use ark_bn254::{Fq as Bn254Fq, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_ff::QuadExtField;
use ark_serialize::CanonicalDeserialize;
use async_trait::async_trait;

use serde::Deserialize;
use std::collections::HashMap;

use crate::types::{OperatorInfo, OperatorPubkeys};

use super::OperatorInfoServiceTrait;

#[derive(Debug, Clone)]
pub struct OperatorsInfoServiceSubgraph<Q>
where
    Q: GraphQLQuerier,
{
    client: Q,
    name: String,
}

#[derive(Debug, Deserialize)]
struct QueryOperatorByAddressGql {
    operator: IndexedOperatorInfoGql,
}

#[derive(Debug, Deserialize)]
struct SocketUpdates {
    socket: String,
}

#[derive(Debug, Deserialize)]
struct IndexedOperatorInfoGql {
    address: String,
    pubkey_g1_x: String,
    pubkey_g1_y: String,
    pubkey_g2_x: Vec<String>,
    pubkey_g2_y: Vec<String>,
    socket_updates: Vec<SocketUpdates>,
}

#[async_trait]
pub trait GraphQLQuerier: Clone + Send + Sync + 'static {
    async fn query<T: serde::de::DeserializeOwned>(
        &self,
        query: &str,
        variables: HashMap<String, String>,
    ) -> Result<T, String>;
}

impl<Q> OperatorsInfoServiceSubgraph<Q>
where
    Q: GraphQLQuerier,
{
    pub fn new(client: Q) -> Self {
        OperatorsInfoServiceSubgraph {
            client,
            name: "OperatorsInfoServiceSubgraph".to_string(),
        }
    }

    async fn get_indexed_operator_info_by_operator_id(
        &self,
        operator: Address,
    ) -> Result<OperatorInfo, String> {
        let query = r#"
            query($id: String!) {
                operator(address: $id) {
                    address
                    pubkeyG1_X
                    pubkeyG1_Y
                    pubkeyG2_X
                    pubkeyG2_Y
                    socketUpdates(first: 1, orderBy: blockNumber, orderDirection: desc) {
                        socket
                    }
                }
            }
        "#;

        let variables = vec![("id".to_string(), format!("0x{}", hex::encode(operator.0)))]
            .into_iter()
            .collect();

        let response: QueryOperatorByAddressGql =
            self.client.query(query, variables).await.map_err(|e| {
                log::error!("Error requesting info for operator: {:?}", e);
                e
            })?;

        convert_indexed_operator_info_gql_to_operator_info(&response.operator)
    }
}

#[async_trait]
impl<Q> OperatorInfoServiceTrait for OperatorsInfoServiceSubgraph<Q>
where
    Q: GraphQLQuerier,
{
    async fn get_operator_info(&self, operator: Address) -> Result<Option<OperatorInfo>, String> {
        let operator_info = self
            .get_indexed_operator_info_by_operator_id(operator)
            .await;
        match operator_info {
            Ok(info) => Ok(Some(info)),
            Err(_) => Ok(None),
        }
    }
}

fn convert_indexed_operator_info_gql_to_operator_info(
    operator: &IndexedOperatorInfoGql,
) -> Result<OperatorInfo, String> {
    if operator.socket_updates.is_empty() {
        return Err("no socket found for operator".to_string());
    }

    let pubkey_g1_x =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g1_x).unwrap()[..])
            .map_err(|_| "Invalid G1 X coordinate".to_string())?;
    let pubkey_g1_y =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g1_y).unwrap()[..])
            .map_err(|_| "Invalid G1 Y coordinate".to_string())?;
    let pubkey_g1 = Bn254G1Affine::new(pubkey_g1_x, pubkey_g1_y);

    let pubkey_g2_x_0 =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g2_x[0]).unwrap()[..])
            .map_err(|_| "Invalid G2 X0 coordinate".to_string())?;
    let pubkey_g2_x_1 =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g2_x[1]).unwrap()[..])
            .map_err(|_| "Invalid G2 X1 coordinate".to_string())?;
    let pubkey_g2_y_0 =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g2_y[0]).unwrap()[..])
            .map_err(|_| "Invalid G2 Y0 coordinate".to_string())?;
    let pubkey_g2_y_1 =
        Bn254Fq::deserialize_compressed(&hex::decode(&operator.pubkey_g2_y[1]).unwrap()[..])
            .map_err(|_| "Invalid G2 Y1 coordinate".to_string())?;
    let pubkey_g2 = Bn254G2Affine::new(
        QuadExtField {
            c0: pubkey_g2_x_0,
            c1: pubkey_g2_x_1,
        },
        QuadExtField {
            c0: pubkey_g2_y_0,
            c1: pubkey_g2_y_1,
        },
    );

    Ok(OperatorInfo {
        socket: operator.socket_updates[0].socket.clone(),
        pubkeys: OperatorPubkeys {
            g1_pubkey: pubkey_g1,
            g2_pubkey: pubkey_g2,
        },
    })
}
