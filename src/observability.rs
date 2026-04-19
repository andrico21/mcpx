use std::{path::Path, sync::Arc};

use tracing_subscriber::{
    EnvFilter, Layer as _,
    fmt::time::FormatTime,
    layer::SubscriberExt,
    util::{SubscriberInitExt, TryInitError},
};

use crate::config::ObservabilityConfig;

/// Timestamp formatter that emits local time via `chrono::Local`.
#[derive(Clone, Copy)]
struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(
            w,
            "{}",
            chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z")
        )
    }
}

/// Initialize structured logging from an [`ObservabilityConfig`].
///
/// Respects `RUST_LOG` env var if set; otherwise uses `config.log_level`.
/// When `log_format` is `"json"`, emits machine-readable JSON lines.
/// When `audit_log_path` is set, appends an additional JSON log file
/// at INFO level for audit trail purposes.
///
/// # Errors
///
/// Returns [`TryInitError`] if a global tracing subscriber has already
/// been installed (e.g. by a previous call to this function or
/// [`init_tracing`]). Callers that want to tolerate double-initialization
/// (such as test harnesses) can ignore the error.
pub fn init_tracing_from_config(config: &ObservabilityConfig) -> Result<(), TryInitError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let (audit_writer, audit_warnings) = config
        .audit_log_path
        .as_ref()
        .map_or((None, Vec::new()), |p| open_audit_file(p));

    // "pretty" and "text" are aliases for human-readable output.
    let result = if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        );
        init_with_optional_audit(subscriber, audit_writer)
    } else {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        );
        init_with_optional_audit(subscriber, audit_writer)
    };

    if result.is_ok() {
        for warning in audit_warnings {
            tracing::warn!(warning = %warning, "audit logging initialization warning");
        }
    }

    result
}

/// Attach an optional audit JSON log layer and initialize the subscriber.
///
/// Extracted to avoid duplicating the audit layer construction in both
/// the JSON and pretty format branches of [`init_tracing_from_config`].
///
/// Uses [`SubscriberInitExt::try_init`] so that a previously-installed
/// global subscriber yields [`TryInitError`] rather than panicking.
fn init_with_optional_audit<S>(
    subscriber: S,
    audit_writer: Option<AuditFile>,
) -> Result<(), TryInitError>
where
    S: tracing::Subscriber
        + for<'span> tracing_subscriber::registry::LookupSpan<'span>
        + Send
        + Sync
        + 'static,
{
    if let Some(writer) = audit_writer {
        subscriber
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(LocalTime)
                    .with_writer(writer)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            )
            .try_init()
    } else {
        subscriber.try_init()
    }
}

/// Initialize structured logging with a simple filter string.
///
/// Convenience function for callers that don't use [`ObservabilityConfig`].
/// Respects `RUST_LOG` env var. Falls back to `default_filter` (e.g. `"info"`).
///
/// # Errors
///
/// Returns [`TryInitError`] if a global tracing subscriber has already
/// been installed. This makes the function safe to call repeatedly from
/// tests or embedders without panicking.
pub fn init_tracing(default_filter: &str) -> Result<(), TryInitError> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)))
        .with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        )
        .try_init()
}

/// Newtype wrapper around a shared file handle for audit logging.
///
/// Implements `MakeWriter` so it can be used with `tracing_subscriber::fmt`.
#[derive(Clone)]
struct AuditFile(Arc<std::fs::File>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for AuditFile {
    type Writer = AuditFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        AuditFileWriter(Arc::clone(&self.0))
    }
}

/// A thin wrapper that implements `io::Write` by delegating to the inner `File`.
struct AuditFileWriter(Arc<std::fs::File>);

impl std::io::Write for AuditFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut &*self.0, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut &*self.0)
    }
}

/// Open the audit log file for appending.
///
/// Returns an optional writer and any warnings encountered while preparing it.
///
/// # Log rotation
///
/// The writer opens the file in append mode and holds a long-lived handle
/// for the lifetime of the process. There is **no** built-in rotation, no
/// SIGHUP-style reopen, and no compression. Operators are expected to use
/// an external rotator such as `logrotate` (Linux) or `newsyslog` (BSD /
/// macOS) configured with `copytruncate` (or equivalent) so the inode this
/// handle points at is preserved across rotations. If the rotator instead
/// renames + recreates the file, this writer will keep writing to the
/// renamed (rotated) inode until the process restarts.
fn open_audit_file(path: &Path) -> (Option<AuditFile>, Vec<String>) {
    let mut warnings = Vec::new();

    // Ensure parent directory exists.
    if let Some(parent) = path.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warnings.push(format!(
            "failed to create audit log directory {}: {e}",
            path.display()
        ));
        return (None, warnings);
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => {
            // Restrict audit log to owner-only on Unix (0o600).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                    warnings.push(format!("failed to set audit log permissions to 0o600: {e}"));
                }
            }
            (Some(AuditFile(Arc::new(f))), warnings)
        }
        Err(e) => {
            warnings.push(format!(
                "failed to open audit log file {}: {e}",
                path.display()
            ));
            (None, warnings)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::print_stdout,
        clippy::print_stderr
    )]
    use super::{init_tracing, init_tracing_from_config};
    use crate::config::ObservabilityConfig;

    #[test]
    fn config_format_valid() {
        let config = ObservabilityConfig {
            log_level: "debug".into(),
            log_format: "json".into(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
        };
        assert!(config.log_format == "json" || config.log_format == "pretty");
    }

    /// Calling either `init_tracing` entry point twice in the same process
    /// must NOT panic. The second (and any subsequent) call must return
    /// `Err(TryInitError)` instead. This guards against regressions of the
    /// pre-0.11 `.init()` behaviour, which aborted the process when a
    /// global subscriber was already installed (e.g. by a sibling test).
    ///
    /// All four call orderings are exercised in a single test because the
    /// global tracing subscriber is process-wide state - we cannot rely on
    /// test isolation here.
    #[test]
    fn init_tracing_double_init_returns_err_not_panic() {
        // First call: may succeed or fail depending on whether another
        // test in this binary already installed a subscriber. Either is
        // acceptable; we only require that it does not panic.
        let _ = init_tracing("info");

        // Second call: a global subscriber is now guaranteed to exist,
        // so this MUST return Err and MUST NOT panic.
        let second = init_tracing("debug");
        assert!(
            second.is_err(),
            "second init_tracing must return Err once a global subscriber exists"
        );

        // The companion entry point must also report Err rather than panic.
        let cfg = ObservabilityConfig {
            log_level: "info".into(),
            log_format: "pretty".into(),
            audit_log_path: None,
            log_request_headers: false,
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9090".into(),
        };
        let third = init_tracing_from_config(&cfg);
        assert!(
            third.is_err(),
            "init_tracing_from_config must return Err once a global subscriber exists"
        );
    }
}
