//! Minimal rmcp-server-kit server example.
//!
//! The smallest working MCP server: Streamable HTTP transport, health
//! endpoints, and the default `ServerHandler`. Add tools by implementing
//! the corresponding `ServerHandler` trait methods — see
//! <https://docs.rs/rmcp> for the handler API.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example minimal_server
//! ```
//!
//! Then, in another shell:
//!
//! ```bash
//! curl http://127.0.0.1:8080/healthz
//! curl http://127.0.0.1:8080/readyz
//! ```

use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};
use rmcp_server_kit::transport::{McpServerConfig, serve};

#[derive(Clone)]
struct MinimalHandler;

impl ServerHandler for MinimalHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> rmcp_server_kit::Result<()> {
    // Ignore the error: the only failure mode is "a global tracing
    // subscriber was already installed", which is harmless for an example
    // that owns the entire process.
    let _ = rmcp_server_kit::observability::init_tracing("info,rmcp_server_kit=debug");

    let config = McpServerConfig::new(
        "127.0.0.1:8080",
        "rmcp-server-kit-minimal-example",
        env!("CARGO_PKG_VERSION"),
    )
    .with_request_timeout(std::time::Duration::from_secs(30))
    .enable_request_header_logging();

    serve(config.validate()?, || MinimalHandler).await
}
