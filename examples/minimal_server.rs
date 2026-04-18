//! Minimal mcpx server example.
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

use mcpx::transport::{McpServerConfig, serve};
use rmcp::{
    handler::server::ServerHandler,
    model::{ServerCapabilities, ServerInfo},
};

#[derive(Clone)]
struct MinimalHandler;

impl ServerHandler for MinimalHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> mcpx::Result<()> {
    // Ignore the error: the only failure mode is "a global tracing
    // subscriber was already installed", which is harmless for an example
    // that owns the entire process.
    let _ = mcpx::observability::init_tracing("info,mcpx=debug");

    let config = McpServerConfig::new(
        "127.0.0.1:8080",
        "mcpx-minimal-example",
        env!("CARGO_PKG_VERSION"),
    )
    .with_request_timeout(std::time::Duration::from_secs(30))
    .enable_request_header_logging();

    serve(config, || MinimalHandler).await
}
