use std::{path::Path, sync::Arc};

use tracing_subscriber::{
    EnvFilter, Layer as _, fmt::time::FormatTime, layer::SubscriberExt, util::SubscriberInitExt,
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
pub fn init_tracing_from_config(config: &ObservabilityConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let (audit_writer, audit_warnings) = config
        .audit_log_path
        .as_ref()
        .map_or((None, Vec::new()), |p| open_audit_file(p));

    // "pretty" and "text" are aliases for human-readable output.
    if config.log_format == "json" {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        );
        init_with_optional_audit(subscriber, audit_writer);
    } else {
        let subscriber = tracing_subscriber::registry().with(filter).with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        );
        init_with_optional_audit(subscriber, audit_writer);
    }

    for warning in audit_warnings {
        tracing::warn!(warning = %warning, "audit logging initialization warning");
    }
}

/// Attach an optional audit JSON log layer and initialize the subscriber.
///
/// Extracted to avoid duplicating the audit layer construction in both
/// the JSON and pretty format branches of [`init_tracing_from_config`].
fn init_with_optional_audit<S>(subscriber: S, audit_writer: Option<AuditFile>)
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
            .init();
    } else {
        subscriber.init();
    }
}

/// Initialize structured logging with a simple filter string.
///
/// Convenience function for callers that don't use [`ObservabilityConfig`].
/// Respects `RUST_LOG` env var. Falls back to `default_filter` (e.g. `"info"`).
pub fn init_tracing(default_filter: &str) {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)))
        .with(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalTime)
                .with_writer(std::io::stderr),
        )
        .init();
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
}
