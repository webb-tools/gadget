use log::{Log, SetLoggerError};
use tracing::dispatcher::SetGlobalDefaultError;
use tracing_log::LogTracer;
use tracing_wasm;
use tracing_wasm::{ConsoleConfig, WASMLayerConfigBuilder};

use super::Logger;

struct WasmLogger {
    logger: &'static dyn Log,
}

impl WasmLogger {
    /// Initializes `WasmLogger`, setting the global logger.
    pub fn setup() -> Result<WasmLogger, SetLoggerError> {
        LogTracer::init()?;
        Ok(WasmLogger {
            logger: log::logger(),
        })
    }

    /// Subscribe with the provided max tracing level, with `tracing::Level::TRACE` being the highest.
    pub fn subscribe(max_level: tracing::Level) -> Result<(), SetGlobalDefaultError> {
        let console_config = ConsoleConfig::ReportWithConsoleColor;
        let mut builder = WASMLayerConfigBuilder::new();
        let config = builder
            .set_report_logs_in_timings(false)
            .set_max_level(max_level)
            .set_console_config(console_config)
            .build();
        tracing_wasm::set_as_global_default_with_config(config);
        Ok(())
    }

    /// Subscribes with the default tracing level, only logging up to the `tracing::Level::INFO` level.
    pub fn subscribe_default() -> Result<(), SetGlobalDefaultError> {
        WasmLogger::subscribe(tracing::Level::INFO)
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

impl Logger for WasmLogger {
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
    use crate::logging::Logger;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);
    use super::WasmLogger;

    #[wasm_bindgen_test]
    fn test_tracing_logger() {
        let logger = WasmLogger::setup().unwrap();
        WasmLogger::subscribe(tracing::Level::TRACE).unwrap();
        logger.debug("test_target", "Debug Test", &["tag1", "tag2"]);
        logger.trace("test_target", "Trace Test", &["tag1", "tag2"]);
        logger.info("test_target", "Info Test", &["tag1", "tag2"]);
        logger.warn("test_target", "Warn Test", &["tag1", "tag2"]);
        logger.error("test_target", "Error Test", &["tag1", "tag2"]);
    }
}
