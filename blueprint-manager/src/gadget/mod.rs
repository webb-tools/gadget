use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub type ActiveShells =
    HashMap<u64, HashMap<u64, (Arc<AtomicBool>, Option<tokio::sync::oneshot::Sender<()>>)>>;
pub mod native;
