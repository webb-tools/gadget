use log::{Log, SetLoggerError};
use tracing::dispatcher::SetGlobalDefaultError;
use tracing_log::LogTracer;

use super::Logger;

struct TracingLogger {
    logger: &'static dyn Log,
}

impl TracingLogger {
    /// Initializes `TracingLogger`, setting the global logger.
    pub fn setup() -> Result<TracingLogger, SetLoggerError> {
        LogTracer::init()?;
        Ok(TracingLogger {
            logger: log::logger(),
        })
    }

    /// Subscribe with the provided max tracing level, with `tracing::Level::TRACE` being the highest.
    pub fn subscribe(max_level: tracing::Level) -> Result<(), SetGlobalDefaultError> {
        let subscriber = tracing_subscriber::fmt()
            .pretty()
            .with_max_level(max_level)
            .with_thread_names(true)
            .with_target(true)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
        Ok(())
    }

    /// Subscribes with the default tracing level, only logging up to the `tracing::Level::INFO` level.
    pub fn subscribe_default() -> Result<(), SetGlobalDefaultError> {
        TracingLogger::subscribe(tracing::Level::INFO)
    }
}

macro_rules! custom_log {
    ($logger:expr, $level:expr, $target:expr, $message:expr, $tags:expr) => {{
        $logger.log(
            &log::Record::builder()
                .args(format_args!("{}", $message))
                .level($level)
                .target($target)
                .build(),
        );
        for tag in $tags {
            $logger.log(
                &log::Record::builder()
                    .args(format_args!("{}", $message))
                    .level($level)
                    .target(tag)
                    .build(),
            );
        }
    }};
}

impl Logger for TracingLogger {
    fn debug(&self, target: &str, message: &str, tags: &[&str]) {
        let logger = self.logger;
        custom_log!(logger, log::Level::Debug, target, message, tags);
    }

    fn error(&self, target: &str, message: &str, tags: &[&str]) {
        let logger = self.logger;
        custom_log!(logger, log::Level::Error, target, message, tags);
    }

    fn info(&self, target: &str, message: &str, tags: &[&str]) {
        let logger = self.logger;
        custom_log!(logger, log::Level::Info, target, message, tags);
    }

    fn trace(&self, target: &str, message: &str, tags: &[&str]) {
        let logger = self.logger;
        custom_log!(logger, log::Level::Trace, target, message, tags);
    }

    fn warn(&self, target: &str, message: &str, tags: &[&str]) {
        let logger = self.logger;
        custom_log!(logger, log::Level::Warn, target, message, tags);
    }
}
#[cfg(test)]
mod test {
    use super::TracingLogger;
    use crate::logging::Logger;

    #[test]
    fn test_tracing_logger() {
        let logger = TracingLogger::setup().unwrap();
        TracingLogger::subscribe(tracing::Level::TRACE).unwrap();
        logger.debug("test_target", "Debug Test", &["tag1", "tag2"]);
        logger.trace("test_target", "Trace Test", &["tag1", "tag2"]);
        logger.info("test_target", "Info Test", &["tag1", "tag2"]);
        logger.warn("test_target", "Warn Test", &["tag1", "tag2"]);
        logger.error("test_target", "Error Test", &["tag1", "tag2"]);
    }
}
