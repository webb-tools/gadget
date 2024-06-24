/// Module for structured logging using the slog crate.
#[cfg(feature = "std")]
pub mod slog;
/// Module for structured logging utilizing the Tracing.
#[cfg(feature = "std")]
pub mod tracing;
/// Module for structured logging in a WASM environment using Tracing.
#[cfg(feature = "wasm")]
pub mod wasm;

/// Trait defining the methods for logging.
pub trait Logger {
    /// Log a debug message.
    fn debug(&self, target: &str, message: &str, tags: &[&str]);

    /// Log an error message.
    fn error(&self, target: &str, message: &str, tags: &[&str]);

    /// Log an info message.
    fn info(&self, target: &str, message: &str, tags: &[&str]);

    /// Log a trace message.
    fn trace(&self, target: &str, message: &str, tags: &[&str]);

    /// Log a warning message.
    fn warn(&self, target: &str, message: &str, tags: &[&str]);
}
