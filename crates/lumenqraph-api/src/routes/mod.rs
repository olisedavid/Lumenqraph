//! Route table. `/health` and `/metrics` are public; everything else sits
//! behind the auth + rate-limit middleware.

pub mod contracts;
pub mod events;
pub mod health;
pub mod liquidity;
pub mod nfts;
pub mod openapi;
pub mod proxy;
pub mod read;
pub mod sdk;
pub mod stats;
pub mod stream;
pub mod swaps;
pub mod transfers;
pub mod webhooks;

use std::sync::Arc;

use async_graphql::http::GraphiQLSource;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse};
use axum::Json;
use axum::routing::{any, delete, get, patch, post};
use axum::{middleware, Extension, Router};
use serde_json::json;
use tower::Layer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::auth::{auth_and_rate_limit, concurrency_limit, rpc_auth_and_rate_limit};
use crate::graphql::{self, AppSchema};
use crate::metrics;
use crate::state::AppState;

/// Execute a GraphQL query against the shared schema.
async fn graphql_handler(schema: Extension<AppSchema>, req: GraphQLRequest) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// Serve the GraphiQL in-browser IDE, pointed at `/graphql`.
async fn graphiql() -> impl IntoResponse {
    let introspection_enabled = std::env::var("GRAPHQL_INTROSPECTION_ENABLED")
        .ok()
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    if !introspection_enabled {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({
                "error": "GraphQL introspection is disabled",
                "message": "Use POST /graphql for queries. Introspection is not available in this environment."
            }))
        ).into_response();
    }

    Html(GraphiQLSource::build().endpoint("/graphql").finish()).into_response()
}

pub fn router(state: AppState) -> Router {
    let schema = graphql::build_schema(state.pool.clone());

    // Public, unauthenticated observability and documentation endpoints.
    let public = Router::new()
        .route("/health", get(health::health))
        .route("/livez", get(health::livez))
        .route("/readyz", get(health::readyz))
        .route("/metrics", get(metrics::metrics))
        .merge(openapi::router());

    // RPC-backed routes with separate, tighter rate limiting (they hit upstream RPC).
    let rpc_routes = Router::new()
        .route("/contracts/:contract_id/call", post(read::call_function))
        .route(
            "/contracts/:contract_id/simulate",
            post(read::simulate_call),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rpc_auth_and_rate_limit,
        ));

    // Data + management endpoints, behind auth + rate limiting.
    let protected = Router::new()
        .route("/contracts", get(contracts::list_contracts))
        .route(
            "/contracts/:contract_id/interface",
            get(contracts::contract_interface),
        )
        .route(
            "/contracts/:contract_id/interface/history",
            get(contracts::contract_interface_history),
        )
        .route(
            "/contracts/:contract_id/interface/diff",
            get(contracts::contract_interface_diff),
        )
        .route(
            "/contracts/:contract_id/state",
            get(contracts::contract_state),
        )
        .route(
            "/contracts/:contract_id/data",
            get(contracts::contract_data),
        )
        .route(
            "/contracts/:contract_id/data/:key_hash",
            get(contracts::contract_data_key),
        )
        .route("/contracts/:contract_id/sdk", get(sdk::contract_sdk))
        .route(
            "/contracts/:contract_id/functions",
            get(read::list_functions),
        )
        .route("/contracts/:contract_id/events", get(events::list_events))
        .route("/contracts/:contract_id/events/stream", get(stream::stream_events))
        .route("/contracts/:contract_id/stats", get(stats::contract_stats))
        .route(
            "/contracts/:contract_id/transfers",
            get(transfers::list_transfers),
        )
        .route(
            "/contracts/:contract_id/liquidity",
            get(liquidity::list_liquidity_events),
        )
        .route(
            "/contracts/:contract_id/nfts",
            get(nfts::list_nft_events),
        )
        .route(
            "/contracts/:contract_id/swaps",
            get(swaps::list_swaps),
        )
        // Single-event and by-transaction lookups (#123, #124).
        .route("/events/:event_id", get(events::get_event))
        .route(
            "/transactions/:tx_hash/events",
            get(events::transaction_events),
        )
        .route(
            "/webhooks",
            post(webhooks::create_webhook).get(webhooks::list_webhooks),
        )
        .route("/webhooks/:id", delete(webhooks::delete_webhook).patch(webhooks::update_webhook))
        .route("/webhooks/:id/deliveries", get(webhooks::list_webhook_deliveries))
        .route("/webhooks/:id/redrive", post(webhooks::redrive_webhook))
        .route("/webhooks/:id/reenable", post(webhooks::reenable_webhook))
        .route("/webhooks/:id/rotate-secret", post(webhooks::rotate_webhook_secret))
        // GraphQL: POST executes queries, GET serves the GraphiQL IDE. Behind
        // the same auth + rate-limit middleware as the REST data routes.
        .route("/graphql", post(graphql_handler).get(graphiql))
        .layer(Extension(schema))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_and_rate_limit,
        ));

    let metrics_collector = state.metrics.clone();
    let mut app = public
        .merge(protected)
        .merge(rpc_routes)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            concurrency_limit,
        ))
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let collector = metrics_collector.clone();
            collector.middleware(req, next)
        }));

    // Sibling instances under a path prefix (see `proxy`). Registered outside
    // the auth middleware: each upstream enforces its own policy.
    if !state.mounts.is_empty() {
        let client = Arc::new(reqwest::Client::new());
        for (name, upstream) in state.mounts.iter() {
            let (client, upstream, prefix) = (
                Arc::clone(&client),
                Arc::new(upstream.clone()),
                Arc::new(format!("/{name}")),
            );
            let handler = move |req: Request| {
                proxy::proxy(
                    Arc::clone(&client),
                    Arc::clone(&upstream),
                    Arc::clone(&prefix),
                    req,
                )
            };
            app = app
                .route(&format!("/{name}"), any(handler.clone()))
                .route(&format!("/{name}/*rest"), any(handler));
        }
    }

    // Serve the static explorer UI at the same origin as the API (so it needs
    // no CORS and no configured API base). Falls back to it for any unmatched
    // path; `/` resolves to explorer/index.html. Dir is configurable so the
    // container image can point at wherever the assets are COPYed.
    let explorer_dir = std::env::var("EXPLORER_DIR").unwrap_or_else(|_| "explorer".to_string());
    if std::path::Path::new(&explorer_dir).is_dir() {
        // `no-cache` means "revalidate before using", not "don't cache":
        // ServeDir serves Last-Modified, so an unchanged explorer costs a 304 —
        // but a deploy shows up on the next load instead of whenever the
        // browser's heuristic cache happens to expire.
        let revalidate = SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        // Strict CSP: disallow inline scripts and restrict sources to same-origin only.
        // Protects against stored XSS from malicious contract data in the explorer UI.
        let csp = SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'"),
        );
        // Prevent MIME-type sniffing (guards against polyglot-file attacks).
        let nosniff = SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        // Prevent the explorer from being embedded in an iframe (clickjacking).
        let no_frame = SetResponseHeaderLayer::if_not_present(
            header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        app.fallback_service(
            no_frame.layer(nosniff.layer(csp.layer(revalidate.layer(ServeDir::new(explorer_dir)))))
        )
    } else {
        app
    }
}
