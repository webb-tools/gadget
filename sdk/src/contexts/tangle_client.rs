use async_trait::async_trait;

/// `TangleClientContext` trait provides access to the Tangle client from the context.
#[async_trait]
pub trait TangleClientContext {
    type Config: subxt::Config;
    /// Get the Tangle client from the context.
    async fn tangle_client(
        &self,
    ) -> color_eyre::Result<subxt::OnlineClient<Self::Config>, subxt::Error>;

    fn get_call_id(&mut self) -> &mut Option<u64>;

    fn set_call_id(&mut self, call_id: u64) {
        *self.get_call_id() = Some(call_id);
    }
}
