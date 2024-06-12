use alloy_primitives::Address;
use async_trait::async_trait;

use crate::types::OperatorInfo;

pub mod graphql;
pub mod in_memory;

#[async_trait]
pub trait OperatorInfoServiceTrait: Send + Sync + Clone + 'static {
    async fn get_operator_info(&self, operator: Address) -> Result<Option<OperatorInfo>, String>;
}
