use slog::{debug, error, info, trace, warn};

use super::Logger;

struct SlogLogger {
    logger: slog::Logger,
}

macro_rules! custom_log {
    ($level:ident, $logger:expr, $target:expr, $message:expr, $tags:expr) => {{
        $level!($logger, "{} {}", $target, $message);
        for tag in $tags {
            $level!($logger, "{} {}", tag, $message);
        }
    }};
}

impl Logger for SlogLogger {
    fn debug(&self, target: &str, message: &str, tags: &[&str]) {
        custom_log!(debug, self.logger, target, message, tags);
    }

    fn error(&self, target: &str, message: &str, tags: &[&str]) {
        custom_log!(error, self.logger, target, message, tags);
    }

    fn info(&self, target: &str, message: &str, tags: &[&str]) {
        custom_log!(info, self.logger, target, message, tags);
    }

    fn trace(&self, target: &str, message: &str, tags: &[&str]) {
        custom_log!(trace, self.logger, target, message, tags);
    }

    fn warn(&self, target: &str, message: &str, tags: &[&str]) {
        custom_log!(warn, self.logger, target, message, tags);
    }
}
#[cfg(test)]
mod test {
    use slog::Drain;

    use crate::logging::Logger;

    use super::SlogLogger;

    #[test]
    fn test_slog_logger() {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
        let inner_logger =
            slog::Logger::root(slog_term::FullFormat::new(plain).build().fuse(), slog::o!());

        let logger = SlogLogger {
            logger: inner_logger,
        };
        logger.debug("test_target", "Debug Test", &["tag1", "tag2"]);
        logger.trace("test_target", "Trace Test", &["tag1", "tag2"]);
        logger.info("test_target", "Info Test", &["tag1", "tag2"]);
        logger.warn("test_target", "Warn Test", &["tag1", "tag2"]);
        logger.error("test_target", "Error Test", &["tag1", "tag2"]);
    }
}
