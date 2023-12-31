use crate::error::TestError;
use crate::message::{TestProtocolMessage, UserID};
use gadget_core::job::JobError;
use gadget_core::job_manager::{ProtocolRemote, SendFuture, ShutdownReason, WorkManagerInterface};
use parking_lot::{Mutex, RwLock};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub struct TestWorkManager {
    pub clock: Arc<RwLock<u64>>,
}

pub struct TestProtocolRemote {
    pub start_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    pub shutdown_tx: Mutex<Option<tokio::sync::oneshot::Sender<ShutdownReason>>>,
    pub associated_session_id: <TestWorkManager as WorkManagerInterface>::SessionID,
    pub associated_block_id: <TestWorkManager as WorkManagerInterface>::Clock,
    pub associated_retry_id: <TestWorkManager as WorkManagerInterface>::RetryID,
    pub to_async_protocol: tokio::sync::mpsc::UnboundedSender<
        <TestWorkManager as WorkManagerInterface>::ProtocolMessage,
    >,
    pub is_done: Arc<AtomicBool>,
}

const ACCEPTABLE_BLOCK_TOLERANCE: u64 = 20;

impl WorkManagerInterface for TestWorkManager {
    type RetryID = u16;
    type UserID = UserID;
    type Clock = u64;
    type ProtocolMessage = TestProtocolMessage;
    type Error = TestError;
    type SessionID = u64;
    type TaskID = [u8; 8];

    fn debug(&self, input: String) {
        log::debug!("{input}")
    }

    fn error(&self, input: String) {
        log::error!("{input}")
    }

    fn warn(&self, input: String) {
        log::warn!("{input}")
    }

    fn clock(&self) -> Self::Clock {
        *self.clock.read()
    }

    fn acceptable_block_tolerance() -> Self::Clock {
        ACCEPTABLE_BLOCK_TOLERANCE
    }
}

impl ProtocolRemote<TestWorkManager> for TestProtocolRemote {
    fn start(&self) -> Result<(), <TestWorkManager as WorkManagerInterface>::Error> {
        self.start_tx
            .lock()
            .take()
            .ok_or_else(|| TestError {
                reason: "Already started".to_string(),
            })?
            .send(())
            .map_err(|_| TestError {
                reason: "Already started".to_string(),
            })
    }

    fn session_id(&self) -> <TestWorkManager as WorkManagerInterface>::SessionID {
        self.associated_session_id
    }

    fn started_at(&self) -> <TestWorkManager as WorkManagerInterface>::Clock {
        self.associated_block_id
    }

    fn shutdown(
        &self,
        reason: ShutdownReason,
    ) -> Result<(), <TestWorkManager as WorkManagerInterface>::Error> {
        self.shutdown_tx
            .lock()
            .take()
            .ok_or_else(|| TestError {
                reason: "Already shutdown".to_string(),
            })?
            .send(reason)
            .map_err(|_| TestError {
                reason: "Already shutdown".to_string(),
            })
    }

    fn is_done(&self) -> bool {
        self.is_done.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn deliver_message(
        &self,
        message: <TestWorkManager as WorkManagerInterface>::ProtocolMessage,
    ) -> Result<(), <TestWorkManager as WorkManagerInterface>::Error> {
        self.to_async_protocol.send(message).map_err(|_| TestError {
            reason: "Failed to deliver message".to_string(),
        })
    }

    fn has_started(&self) -> bool {
        self.start_tx.lock().is_none()
    }

    fn retry_id(&self) -> <TestWorkManager as WorkManagerInterface>::RetryID {
        self.associated_retry_id
    }
}

pub struct TestAsyncProtocolParameters<B> {
    pub is_done: Arc<AtomicBool>,
    pub protocol_message_rx: tokio::sync::mpsc::UnboundedReceiver<
        <TestWorkManager as WorkManagerInterface>::ProtocolMessage,
    >,
    pub start_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    pub shutdown_rx: Option<tokio::sync::oneshot::Receiver<ShutdownReason>>,
    pub associated_block_id: <TestWorkManager as WorkManagerInterface>::Clock,
    pub associated_retry_id: <TestWorkManager as WorkManagerInterface>::RetryID,
    pub associated_session_id: <TestWorkManager as WorkManagerInterface>::SessionID,
    pub associated_task_id: <TestWorkManager as WorkManagerInterface>::TaskID,
    pub test_bundle: B,
}

pub trait AsyncProtocolGenerator<B>:
    Send
    + Sync
    + Fn(TestAsyncProtocolParameters<B>) -> Pin<Box<dyn SendFuture<'static, Result<(), JobError>>>>
{
}

impl<
        B: Send + Sync,
        T: Send
            + Sync
            + Fn(
                TestAsyncProtocolParameters<B>,
            ) -> Pin<Box<dyn SendFuture<'static, Result<(), JobError>>>>,
    > AsyncProtocolGenerator<B> for T
{
}
