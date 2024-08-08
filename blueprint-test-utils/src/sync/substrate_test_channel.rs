use crate::sync::tracked_callback_channel::TrackedCallbackChannel;
use sp_io::TestExternalities;
use std::any::Any;

pub struct MultiThreadedTestExternalities {
    pub tx: TrackedCallbackChannel<InputFunction, Box<dyn Any + Send>>,
}

impl Clone for MultiThreadedTestExternalities {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

pub type InputFunction = Box<dyn FnOnce() -> Box<dyn Any + Send> + 'static + Send>;

impl MultiThreadedTestExternalities {
    pub fn new(mut test_externalities: TestExternalities) -> Self {
        let (tx, mut rx) = TrackedCallbackChannel::new(1024);
        let tx_clone = tx.clone();

        std::thread::spawn(move || {
            while let Some(mut resp) = rx.blocking_recv() {
                let payload: InputFunction = resp.payload();
                let res = test_externalities.execute_with(payload);
                let response = resp.new(res);
                if let Err(err) = tx_clone.try_reply(response) {
                    log::warn!(target: "gadget", "Failed to reply to callback: {err:?}");
                }
            }
        });

        Self { tx }
    }

    pub fn execute_with<T: FnOnce() -> R + Send + 'static, R: Send + 'static>(
        &self,
        function: T,
    ) -> R {
        let wrapped_function = move || {
            let out = function();
            Box::new(out) as Box<dyn Any + Send>
        };
        let response = self
            .tx
            .blocking_send(Box::new(wrapped_function))
            .expect("Failed to receive response") as Box<dyn Any>;

        *response.downcast::<R>().expect("Should downcast")
    }

    pub async fn execute_with_async<T: FnOnce() -> R + Send + 'static, R: Send + 'static>(
        &self,
        function: T,
    ) -> R {
        let wrapped_function = move || {
            let out = function();
            Box::new(out) as Box<dyn Any + Send>
        };
        let response = self
            .tx
            .send(Box::new(wrapped_function))
            .await
            .expect("Failed to receive response") as Box<dyn Any>;

        *response.downcast::<R>().expect("Should downcast")
    }
}
