//! Opt-in tool-call instrumentation for `ServerHandler` implementations.
//!
//! [`crate::tool_hooks::HookedHandler`] wraps any [`rmcp::ServerHandler`] with:
//!
//! - **Before hooks** (async) that observe `(tool_name, arguments, identity,
//!   role, sub, request_id)` and may [`HookOutcome::Continue`](crate::tool_hooks::HookOutcome::Continue),
//!   [`HookOutcome::Deny`](crate::tool_hooks::HookOutcome::Deny), or
//!   [`HookOutcome::Replace`](crate::tool_hooks::HookOutcome::Replace) the call.
//! - **After hooks** (async) that observe the same context plus a
//!   [`HookDisposition`](crate::tool_hooks::HookDisposition) describing how the call resolved and the
//!   approximate result size in bytes.  After-hooks are spawned via
//!   `tokio::spawn` and never block the response path.
//! - **Result-size capping**: serialized tool results larger than
//!   `max_result_bytes` are replaced with a structured error, preventing
//!   token-expensive or memory-expensive payloads from reaching clients.
//!   The cap applies both to inner-handler results and to
//!   [`HookOutcome::Replace`](crate::tool_hooks::HookOutcome::Replace) payloads.
//!
//! This is entirely **opt-in** at the application layer - `rmcp_server_kit::serve()`
//! does not wrap handlers automatically.  Applications that want hooks do:
//!
//! ```no_run
//! use std::sync::Arc;
//! use rmcp_server_kit::tool_hooks::{HookedHandler, HookOutcome, ToolHooks, with_hooks};
//!
//! # #[derive(Clone, Default)]
//! # struct MyHandler;
//! # impl rmcp::ServerHandler for MyHandler {}
//! let handler = MyHandler::default();
//! let hooks = Arc::new(
//!     ToolHooks::new()
//!         .with_max_result_bytes(256 * 1024)
//!         .with_before(Arc::new(|_ctx| Box::pin(async { HookOutcome::Continue })))
//!         .with_after(Arc::new(|_ctx, _disp, _bytes| Box::pin(async {}))),
//! );
//! let _wrapped = with_hooks(handler, hooks);
//! ```

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Content, GetPromptRequestParams, GetPromptResult,
        InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResult, ServerInfo, Tool,
    },
    service::RequestContext,
};

/// Context passed to before/after hooks for a single tool call.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ToolCallContext {
    /// Tool name being invoked.
    pub tool_name: String,
    /// JSON arguments as sent by the client (may be `None`).
    pub arguments: Option<serde_json::Value>,
    /// Identity name from the authenticated request, if any.
    pub identity: Option<String>,
    /// RBAC role associated with the request, if any.
    pub role: Option<String>,
    /// OAuth `sub` claim, if present.
    pub sub: Option<String>,
    /// Raw JSON-RPC request id rendered as a string, if available.
    pub request_id: Option<String>,
}

impl ToolCallContext {
    /// Construct a [`ToolCallContext`] with the given tool name and all
    /// optional fields cleared.  Primarily for use in unit tests and
    /// benchmarks of user-supplied hooks; the runtime path populates
    /// these fields from the request and task-local RBAC state.
    #[must_use]
    pub fn for_tool(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            arguments: None,
            identity: None,
            role: None,
            sub: None,
            request_id: None,
        }
    }
}

/// Outcome returned by a [`BeforeHook`] to control invocation flow.
///
/// - [`HookOutcome::Continue`] - proceed with the wrapped handler.
/// - [`HookOutcome::Deny`] - reject the call with the supplied
///   [`ErrorData`]; the inner handler is **not** called.
/// - [`HookOutcome::Replace`] - return the supplied result instead of
///   invoking the inner handler.  The result is still subject to
///   `max_result_bytes` capping.
#[derive(Debug)]
#[non_exhaustive]
pub enum HookOutcome {
    /// Proceed with the wrapped handler.
    Continue,
    /// Reject the call.  The error is propagated to the client as-is.
    Deny(ErrorData),
    /// Skip the inner handler and return the supplied result instead.
    Replace(Box<CallToolResult>),
}

/// How a tool call resolved, passed to the [`AfterHook`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HookDisposition {
    /// The inner handler ran and returned `Ok`.
    InnerExecuted,
    /// The inner handler ran and returned `Err`.
    InnerErrored,
    /// The before-hook returned [`HookOutcome::Deny`].
    DeniedBefore,
    /// The before-hook returned [`HookOutcome::Replace`].
    ReplacedBefore,
    /// The result (from inner or replace) exceeded `max_result_bytes`
    /// and was substituted with a structured error.
    ResultTooLarge,
}

/// Async before-hook callback type.
///
/// Returns a [`HookOutcome`] controlling whether the inner handler runs.
/// The borrow of `ToolCallContext` is held for the duration of the
/// returned future, which avoids forcing implementations to clone the
/// context for every invocation.
pub type BeforeHook = Arc<
    dyn for<'a> Fn(&'a ToolCallContext) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'a>>
        + Send
        + Sync
        + 'static,
>;

/// Async after-hook callback type.
///
/// Receives the call context, a [`HookDisposition`] describing how the
/// call resolved, and the approximate serialized result size in bytes
/// (`0` for `DeniedBefore` and `InnerErrored`).  Spawned via
/// `tokio::spawn`, so it must not assume it runs before the response is
/// flushed.
pub type AfterHook = Arc<
    dyn for<'a> Fn(
            &'a ToolCallContext,
            HookDisposition,
            usize,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send
        + Sync
        + 'static,
>;

/// Opt-in hooks applied by [`crate::tool_hooks::HookedHandler`].
#[allow(clippy::struct_field_names, reason = "before/after read naturally")]
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ToolHooks {
    /// Hard cap on serialized `CallToolResult` size in bytes.  When
    /// exceeded, the result is replaced with an `is_error=true` result
    /// carrying a `result_too_large` structured error.  `None` disables
    /// the cap.
    pub max_result_bytes: Option<usize>,
    /// Optional before-hook invoked after arg deserialization, before
    /// the wrapped handler is called.
    pub before: Option<BeforeHook>,
    /// Optional after-hook invoked once per call, regardless of how the
    /// call resolved.  Spawned via `tokio::spawn` and never blocks the
    /// response path.
    pub after: Option<AfterHook>,
}

impl ToolHooks {
    /// Construct an empty [`ToolHooks`] with no cap and no hooks.
    ///
    /// Use the `with_*` builder methods to populate fields; this avoids
    /// the `#[non_exhaustive]` restriction that prevents struct-literal
    /// construction from outside the crate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the serialized result size cap in bytes.
    #[must_use]
    pub fn with_max_result_bytes(mut self, max: usize) -> Self {
        self.max_result_bytes = Some(max);
        self
    }

    /// Set the before-hook.
    #[must_use]
    pub fn with_before(mut self, before: BeforeHook) -> Self {
        self.before = Some(before);
        self
    }

    /// Set the after-hook.
    #[must_use]
    pub fn with_after(mut self, after: AfterHook) -> Self {
        self.after = Some(after);
        self
    }
}

impl fmt::Debug for ToolHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolHooks")
            .field("max_result_bytes", &self.max_result_bytes)
            .field("before", &self.before.as_ref().map(|_| "<fn>"))
            .field("after", &self.after.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// `ServerHandler` wrapper that applies [`ToolHooks`].
#[derive(Clone)]
pub struct HookedHandler<H: ServerHandler> {
    inner: Arc<H>,
    hooks: Arc<ToolHooks>,
}

impl<H: ServerHandler> fmt::Debug for HookedHandler<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HookedHandler")
            .field("hooks", &self.hooks)
            .finish_non_exhaustive()
    }
}

/// Construct a [`crate::tool_hooks::HookedHandler`] from an inner handler and hooks.
///
/// Returning the wrapped handler is the entire point of this function;
/// dropping it on the floor would silently disable the supplied hooks.
#[must_use]
pub fn with_hooks<H: ServerHandler>(inner: H, hooks: Arc<ToolHooks>) -> HookedHandler<H> {
    HookedHandler {
        inner: Arc::new(inner),
        hooks,
    }
}

impl<H: ServerHandler> HookedHandler<H> {
    /// Access the wrapped handler.
    #[must_use]
    pub fn inner(&self) -> &H {
        &self.inner
    }

    fn build_context(request: &CallToolRequestParams, req_id: Option<String>) -> ToolCallContext {
        ToolCallContext {
            tool_name: request.name.to_string(),
            arguments: request.arguments.clone().map(serde_json::Value::Object),
            identity: crate::rbac::current_identity(),
            role: crate::rbac::current_role(),
            sub: crate::rbac::current_sub(),
            request_id: req_id,
        }
    }

    /// Spawn the after-hook on the current Tokio runtime.  The future
    /// captures clones of `ctx` and the `Arc<AfterHook>` so it can run
    /// independently of the request task; panics inside the after-hook
    /// are caught by Tokio and never poison the response path.
    ///
    /// The spawned task is **instrumented** with the request span via
    /// [`tracing::Instrument`] and re-establishes the per-request RBAC
    /// task-locals (role, identity, token, sub) via
    /// [`crate::rbac::with_rbac_scope`]. Without this, after-hooks lose
    /// their parent span (breaking trace correlation) and observe
    /// `current_role()` / `current_identity()` as `None`.
    fn spawn_after(
        after: Option<&Arc<AfterHookHolder>>,
        ctx: ToolCallContext,
        disposition: HookDisposition,
        size: usize,
    ) {
        if let Some(after) = after {
            use tracing::Instrument;

            let after = Arc::clone(after);
            // Capture the request span before leaving the request task so
            // after-hook log lines are correlated with the originating call.
            let span = tracing::Span::current();
            // Snapshot RBAC task-locals; defaults are empty strings so the
            // re-established scope is a no-op when the request had no
            // authenticated identity (e.g. health checks, anonymous tools).
            let role = crate::rbac::current_role().unwrap_or_default();
            let identity = crate::rbac::current_identity().unwrap_or_default();
            let token = crate::rbac::current_token()
                .unwrap_or_else(|| secrecy::SecretString::from(String::new()));
            let sub = crate::rbac::current_sub().unwrap_or_default();
            tokio::spawn(
                async move {
                    crate::rbac::with_rbac_scope(role, identity, token, sub, async move {
                        let fut = (after.f)(&ctx, disposition, size);
                        fut.await;
                    })
                    .await;
                }
                .instrument(span),
            );
        }
    }
}

/// Internal newtype that owns the [`AfterHook`] so we can `Arc::clone`
/// the *holder* and let the spawned task borrow `ctx` for the lifetime
/// of the future without lifetime acrobatics in `tokio::spawn`.
struct AfterHookHolder {
    f: AfterHook,
}

/// Structured error body returned when a result exceeds `max_result_bytes`.
fn too_large_result(limit: usize, actual: usize, tool: &str) -> CallToolResult {
    let body = serde_json::json!({
        "error": "result_too_large",
        "message": format!(
            "tool '{tool}' result of {actual} bytes exceeds the configured \
             max_result_bytes={limit}; ask for a narrower query"
        ),
        "limit_bytes": limit,
        "actual_bytes": actual,
    });
    let mut r = CallToolResult::error(vec![Content::text(body.to_string())]);
    r.structured_content = None;
    r
}

fn serialized_size(result: &CallToolResult) -> usize {
    serde_json::to_vec(result).map_or(0, |v| v.len())
}

/// Apply the `max_result_bytes` cap to a result.  Returns the (possibly
/// replaced) result, the size used for accounting, and whether the cap
/// fired.
fn apply_size_cap(
    result: CallToolResult,
    max: Option<usize>,
    tool: &str,
) -> (CallToolResult, usize, bool) {
    let size = serialized_size(&result);
    if let Some(limit) = max
        && size > limit
    {
        tracing::warn!(
            tool = %tool,
            size_bytes = size,
            limit_bytes = limit,
            "tool result exceeds max_result_bytes; replacing with structured error"
        );
        let replaced = too_large_result(limit, size, tool);
        return (replaced, size, true);
    }
    (result, size, false)
}

impl<H: ServerHandler> ServerHandler for HookedHandler<H> {
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        self.inner.initialize(request, context).await
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.inner.list_tools(request, context).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        self.inner.list_prompts(request, context).await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        self.inner.get_prompt(request, context).await
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.inner.list_resources(request, context).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.inner.list_resource_templates(request, context).await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        self.inner.read_resource(request, context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let req_id = Some(format!("{:?}", context.id));
        let ctx = Self::build_context(&request, req_id);
        let max = self.hooks.max_result_bytes;
        let after_holder = self
            .hooks
            .after
            .as_ref()
            .map(|f| Arc::new(AfterHookHolder { f: Arc::clone(f) }));

        // Before hook: may Continue, Deny, or Replace.
        if let Some(before) = self.hooks.before.as_ref() {
            let outcome = before(&ctx).await;
            match outcome {
                HookOutcome::Continue => {}
                HookOutcome::Deny(err) => {
                    Self::spawn_after(after_holder.as_ref(), ctx, HookDisposition::DeniedBefore, 0);
                    return Err(err);
                }
                HookOutcome::Replace(boxed) => {
                    let (final_result, size, capped) = apply_size_cap(*boxed, max, &ctx.tool_name);
                    let disposition = if capped {
                        HookDisposition::ResultTooLarge
                    } else {
                        HookDisposition::ReplacedBefore
                    };
                    Self::spawn_after(after_holder.as_ref(), ctx, disposition, size);
                    return Ok(final_result);
                }
            }
        }

        // Inner handler.
        let result = self.inner.call_tool(request, context).await;

        match result {
            Ok(ok) => {
                let (final_result, size, capped) = apply_size_cap(ok, max, &ctx.tool_name);
                let disposition = if capped {
                    HookDisposition::ResultTooLarge
                } else {
                    HookDisposition::InnerExecuted
                };
                Self::spawn_after(after_holder.as_ref(), ctx, disposition, size);
                Ok(final_result)
            }
            Err(e) => {
                Self::spawn_after(after_holder.as_ref(), ctx, HookDisposition::InnerErrored, 0);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use rmcp::{
        ErrorData, RoleServer, ServerHandler,
        model::{CallToolRequestParams, CallToolResult, Content, ServerInfo},
        service::RequestContext,
    };

    use super::*;

    /// Minimal in-process `ServerHandler` for tests.
    #[derive(Clone, Default)]
    struct TestHandler {
        /// When Some, `call_tool` returns a body of this many 'x' bytes.
        body_bytes: Option<usize>,
    }

    impl ServerHandler for TestHandler {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::default()
        }

        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResult, ErrorData> {
            let body = "x".repeat(self.body_bytes.unwrap_or(4));
            Ok(CallToolResult::success(vec![Content::text(body)]))
        }
    }

    fn ctx(name: &str) -> ToolCallContext {
        ToolCallContext {
            tool_name: name.to_owned(),
            arguments: None,
            identity: None,
            role: None,
            sub: None,
            request_id: None,
        }
    }

    #[tokio::test]
    async fn size_cap_replaces_oversized_result() {
        let inner = TestHandler {
            body_bytes: Some(8_192),
        };
        let hooks = Arc::new(ToolHooks {
            max_result_bytes: Some(256),
            before: None,
            after: None,
        });
        let hooked = with_hooks(inner, hooks);

        let small = CallToolResult::success(vec![Content::text("ok".to_owned())]);
        assert!(serialized_size(&small) < 256);

        let big = CallToolResult::success(vec![Content::text("x".repeat(8_192))]);
        let size = serialized_size(&big);
        assert!(size > 256);

        let (replaced, accounted, capped) = apply_size_cap(big, Some(256), "whatever");
        assert!(capped);
        assert_eq!(accounted, size);
        assert_eq!(replaced.is_error, Some(true));
        assert!(matches!(
            &replaced.content[0].raw,
            rmcp::model::RawContent::Text(t) if t.text.contains("result_too_large")
        ));

        // Compile-check that HookedHandler instantiates with the test inner.
        let _ = hooked;
    }

    #[tokio::test]
    async fn before_hook_deny_builds_error() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let before: BeforeHook = Arc::new(move |ctx_ref| {
            let c = Arc::clone(&c);
            let name = ctx_ref.tool_name.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
                if name == "forbidden" {
                    HookOutcome::Deny(ErrorData::invalid_request("nope", None))
                } else {
                    HookOutcome::Continue
                }
            })
        });

        let hooks = Arc::new(ToolHooks {
            max_result_bytes: None,
            before: Some(before),
            after: None,
        });
        let hooked = with_hooks(TestHandler::default(), hooks);

        let bad_ctx = ctx("forbidden");
        let before_fn = hooked.hooks.before.as_ref().unwrap();
        let outcome = before_fn(&bad_ctx).await;
        assert!(matches!(outcome, HookOutcome::Deny(_)));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        let ok_ctx = ctx("allowed");
        let outcome2 = before_fn(&ok_ctx).await;
        assert!(matches!(outcome2, HookOutcome::Continue));
        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn too_large_result_mentions_limit_and_actual() {
        let r = too_large_result(100, 500, "my_tool");
        let body = serde_json::to_string(&r).unwrap();
        assert!(body.contains("result_too_large"));
        assert!(body.contains("my_tool"));
        assert!(body.contains("100"));
        assert!(body.contains("500"));
    }

    #[tokio::test]
    async fn replace_outcome_skips_inner_and_returns_payload() {
        // Returning Replace from before-hook must yield the supplied
        // CallToolResult directly, with no need for the inner handler.
        let before: BeforeHook = Arc::new(|_ctx| {
            Box::pin(async {
                HookOutcome::Replace(Box::new(CallToolResult::success(vec![Content::text(
                    "from-replace".to_owned(),
                )])))
            })
        });
        let hooks = Arc::new(ToolHooks {
            max_result_bytes: None,
            before: Some(before),
            after: None,
        });
        let _hooked = with_hooks(TestHandler::default(), Arc::clone(&hooks));

        // Exercise the before-hook closure + apply_size_cap helper directly,
        // matching the established test pattern in this module.
        let outcome = (hooks.before.as_ref().unwrap())(&ctx("any")).await;
        let HookOutcome::Replace(boxed) = outcome else {
            panic!("expected HookOutcome::Replace");
        };
        let (result, size, capped) = apply_size_cap(*boxed, None, "any");
        assert!(!capped);
        assert!(size > 0);
        assert!(!result.is_error.unwrap_or(false));
        assert!(matches!(
            &result.content[0].raw,
            rmcp::model::RawContent::Text(t) if t.text == "from-replace"
        ));
    }

    #[tokio::test]
    async fn replace_outcome_subject_to_size_cap() {
        // A Replace payload that exceeds max_result_bytes must be rewritten
        // to result_too_large just like an inner-handler result would be,
        // and the disposition must reflect ResultTooLarge.
        let huge = CallToolResult::success(vec![Content::text("y".repeat(8_192))]);
        let huge_size = serialized_size(&huge);
        assert!(huge_size > 256);

        let (final_result, accounted, capped) = apply_size_cap(huge, Some(256), "replaced_tool");
        assert!(capped);
        assert_eq!(accounted, huge_size);
        assert_eq!(final_result.is_error, Some(true));
        assert!(matches!(
            &final_result.content[0].raw,
            rmcp::model::RawContent::Text(t) if t.text.contains("result_too_large")
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_hook_fires_exactly_once_via_spawn() {
        // spawn_after must enqueue the after-hook exactly one time per
        // invocation and never block the caller; we wait for the spawned
        // task to run by polling the counter with a short timeout.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        let after: AfterHook = Arc::new(move |_ctx, _disp, _size| {
            let c = Arc::clone(&c);
            Box::pin(async move {
                c.fetch_add(1, Ordering::Relaxed);
            })
        });
        let holder = Arc::new(AfterHookHolder { f: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("t"),
            HookDisposition::InnerExecuted,
            42,
        );

        // Wait up to 1s for the spawned task to run.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while counter.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_hook_panic_is_isolated_from_response_path() {
        // A panicking after-hook must not affect the request task.  We
        // spawn a panicking after-hook and then verify the current task
        // can still complete an unrelated future to completion.
        let after: AfterHook = Arc::new(|_ctx, _disp, _size| {
            Box::pin(async {
                panic!("intentional panic in after-hook");
            })
        });
        let holder = Arc::new(AfterHookHolder { f: after });

        HookedHandler::<TestHandler>::spawn_after(
            Some(&holder),
            ctx("boom"),
            HookDisposition::InnerExecuted,
            0,
        );

        // Give Tokio a chance to run + abort the panicking task, then
        // confirm we're still alive and the runtime is healthy.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let still_alive = tokio::spawn(async { 1_u32 + 2 }).await.unwrap();
        assert_eq!(still_alive, 3);
    }
}
