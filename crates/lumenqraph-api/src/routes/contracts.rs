//! `GET /contracts` — the set of contracts we've seen events for, with counts.
//! Derived on the fly from the events table so it can never drift from reality.
//!
//! `GET /contracts/:id/interface` — the contract's decoded on-chain interface
//! (functions, events, and user-defined types), parsed from its deployed WASM.
//!
//! `GET /contracts/:id/interface/history` and `/interface/diff` — the upgrade
//! watch: a Soroban contract can be upgraded in place, so its interface is a
//! time series, and these serve its versions and what changed between them.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use lumenqraph_core::{Contract, SpecDiff};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::types::Json as SqlxJson;

use crate::error::{ApiError, ApiResult};
use crate::specs::CachedSpec;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct ContractsQuery {
    /// Maximum number of contracts to return. Default 100, max 1000.
    #[serde(default = "default_limit")]
    limit: i64,
    /// Cursor-based pagination: the `contract_id` returned as `next_cursor`
    /// from a previous response. When supplied, returns contracts whose
    /// `contract_id` sorts after this value (within the same event-count order).
    #[serde(default)]
    after: Option<String>,
}

fn default_limit() -> i64 {
    100
}

#[derive(Serialize)]
pub struct ContractsResponse {
    pub data: Vec<Contract>,
    pub has_more: bool,
    /// The `after` value to pass on the next request to continue pagination.
    /// `null` when there are no more pages.
    pub next_cursor: Option<String>,
}

pub async fn list_contracts(
    State(state): State<AppState>,
    Query(q): Query<ContractsQuery>,
) -> ApiResult<Json<ContractsResponse>> {
    // Query from the contract_summaries table (maintained by a trigger on events inserts)
    // instead of computing a GROUP BY on every request. This provides constant-time
    // performance independent of the total event count, making the explorer's landing
    // page (which relies on this endpoint) performant at scale.
    //
    // Cursor pagination: when `after` is provided, resolve the event_count of the
    // cursor row and continue from there. Ties in event_count are broken by
    // contract_id (lexicographic), which gives a stable total order without a
    // sequential scan.
    let limit = q.limit.clamp(1, 1000);

    let contracts: Vec<Contract> = if let Some(ref cursor) = q.after {
        // Look up the event_count of the cursor contract so we can use a
        // keyset predicate instead of OFFSET, keeping the query O(log N).
        let cursor_count: Option<i64> = sqlx::query_scalar(
            "SELECT event_count FROM contract_summaries WHERE contract_id = $1",
        )
        .bind(cursor)
        .fetch_optional(&state.pool)
        .await?;

        match cursor_count {
            Some(cc) => sqlx::query_as(
                "SELECT contract_id,
                        event_count,
                        first_seen_ledger,
                        last_seen_ledger
                 FROM contract_summaries
                 WHERE event_count > 0
                   AND (event_count < $1
                        OR (event_count = $1 AND contract_id > $2))
                 ORDER BY event_count DESC, contract_id ASC
                 LIMIT $3",
            )
            .bind(cc)
            .bind(cursor)
            .bind(limit + 1)
            .fetch_all(&state.pool)
            .await?,
            // Unknown cursor — return empty rather than silently restarting.
            None => vec![],
        }
    } else {
        sqlx::query_as(
            "SELECT contract_id,
                    event_count,
                    first_seen_ledger,
                    last_seen_ledger
             FROM contract_summaries
             WHERE event_count > 0
             ORDER BY event_count DESC, contract_id ASC
             LIMIT $1",
        )
        .bind(limit + 1)
        .fetch_all(&state.pool)
        .await?
    };

    let has_more = contracts.len() as i64 > limit;
    let result_contracts: Vec<Contract> = if has_more {
        contracts.into_iter().take(limit as usize).collect()
    } else {
        contracts
    };

    let next_cursor = if has_more {
        result_contracts.last().map(|c| c.contract_id.clone())
    } else {
        None
    };

    Ok(Json(ContractsResponse {
        data: result_contracts,
        has_more,
        next_cursor,
    }))
}

#[derive(Deserialize)]
pub struct InterfaceQuery {
    /// A historical version to serve instead of the current interface.
    version: Option<i32>,
}

pub async fn contract_interface(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(q): Query<InterfaceQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    if let Some(version) = q.version {
        return contract_interface_at_version(&state, &contract_id, version, &headers).await;
    }

    let row: Option<(SqlxJson<Value>, bool, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT interface, has_events, fetched_at, wasm_hash
         FROM contract_specs WHERE contract_id = $1",
    )
    .bind(&contract_id)
    .fetch_optional(&state.pool)
    .await?;

    match row {
        Some((interface, has_events, fetched_at, wasm_hash)) => {
            let etag = generate_etag(&wasm_hash);
            if check_if_none_match(&headers, &etag) {
                return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
            }
            let mut response = Json(json!({
                "contract_id": contract_id,
                "has_events": has_events,
                "fetched_at": fetched_at,
                "interface": interface.0,
            })).into_response();
            response.headers_mut().insert(header::ETAG, etag.parse().unwrap());
            Ok(response)
        },
        None => Err(ApiError::not_found(
            "no on-chain interface indexed for this contract yet",
        )),
    }
}

/// The interface as it was at one historical version — what the contract's
/// callers were binding to back then, which the current interface can't tell you
/// once the contract has been upgraded.
async fn contract_interface_at_version(
    state: &AppState,
    contract_id: &str,
    version: i32,
    headers: &HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let row: Option<(SqlxJson<Value>, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT interface, wasm_hash, observed_at FROM contract_spec_versions
         WHERE contract_id = $1 AND version = $2",
    )
    .bind(contract_id)
    .bind(version)
    .fetch_optional(&state.pool)
    .await?;

    match row {
        Some((interface, wasm_hash, observed_at)) => {
            let etag = generate_etag(&wasm_hash);
            if check_if_none_match(headers, &etag) {
                return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
            }
            let mut response = Json(json!({
                "contract_id": contract_id,
                "version": version,
                "wasm_hash": wasm_hash,
                "observed_at": observed_at,
                "interface": interface.0,
            })).into_response();
            response.headers_mut().insert(header::ETAG, etag.parse().unwrap());
            Ok(response)
        },
        None => Err(ApiError::not_found(format!(
            "no version {version} recorded for this contract"
        ))),
    }
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// How many versions to return, newest first.
    #[serde(default = "default_history_limit")]
    limit: i64,
}

fn default_history_limit() -> i64 {
    50
}

/// `GET /contracts/:id/interface/history` — every interface version we've
/// observed for this contract, newest first, each with the diff against the one
/// before it. The full interface of each version is omitted (fetch it with
/// `/interface?version=N`); the diff is what's interesting here.
pub async fn contract_interface_history(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(q): Query<HistoryQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    let limit = q.limit.clamp(1, 200);
    // Get the latest version for ETag
    let latest_version: Option<i32> = sqlx::query_scalar(
        "SELECT max(version) FROM contract_spec_versions WHERE contract_id = $1",
    )
    .bind(&contract_id)
    .fetch_one(&state.pool)
    .await?;

    let Some(latest_version) = latest_version else {
        return Err(ApiError::not_found(
            "no on-chain interface indexed for this contract yet",
        ));
    };

    let etag = generate_etag(&format!("{}:{}", contract_id, latest_version));
    if check_if_none_match(&headers, &etag) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }

    // (version, wasm_hash, previous_wasm_hash, diff, breaking, observed_at)
    type VersionRow = (
        i32,
        String,
        Option<String>,
        Option<SqlxJson<Value>>,
        bool,
        DateTime<Utc>,
    );
    let rows: Vec<VersionRow> = sqlx::query_as(
        "SELECT version, wasm_hash, previous_wasm_hash, diff, breaking, observed_at
         FROM contract_spec_versions
         WHERE contract_id = $1
         ORDER BY version DESC LIMIT $2",
    )
    .bind(&contract_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let versions: Vec<Value> = rows
        .into_iter()
        .map(
            |(version, wasm_hash, previous_wasm_hash, diff, breaking, observed_at)| {
                json!({
                    "version": version,
                    "wasm_hash": wasm_hash,
                    "previous_wasm_hash": previous_wasm_hash,
                    // Null on version 1: a baseline has nothing to be diffed
                    // against, which is not the same as an empty diff.
                    "diff": diff.map(|d| d.0),
                    "breaking": breaking,
                    "observed_at": observed_at,
                })
            },
        )
        .collect();

    let mut response = Json(json!({
        "contract_id": contract_id,
        "count": versions.len(),
        "versions": versions,
    })).into_response();
    response.headers_mut().insert(header::ETAG, etag.parse().unwrap());
    Ok(response)
}

#[derive(Deserialize)]
pub struct DiffQuery {
    /// Defaults to the version before `to`.
    from: Option<i32>,
    /// Defaults to the newest version.
    to: Option<i32>,
}

/// `GET /contracts/:id/interface/diff?from=&to=` — what changed between any two
/// interface versions.
///
/// Computed on demand from each version's stored spec section rather than read
/// from the `diff` column, which only ever holds consecutive diffs: this way you
/// can ask "what changed between v1 and v5" in one call, not four.
pub async fn contract_interface_diff(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(q): Query<DiffQuery>,
) -> ApiResult<Json<Value>> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    let latest: Option<i32> = sqlx::query_scalar(
        "SELECT max(version) FROM contract_spec_versions WHERE contract_id = $1",
    )
    .bind(&contract_id)
    .fetch_one(&state.pool)
    .await?;
    let Some(latest) = latest else {
        return Err(ApiError::not_found(
            "no on-chain interface indexed for this contract yet",
        ));
    };

    let to = q.to.unwrap_or(latest);
    let from = q.from.unwrap_or(to - 1);
    if from < 1 {
        return Err(ApiError::bad_request(format!(
            "no version to diff against: this contract has only version {latest} on record, \
             so there is no earlier interface to compare it to"
        )));
    }
    if from == to {
        return Err(ApiError::bad_request(
            "`from` and `to` are the same version; nothing to diff",
        ));
    }

    let old = load_spec(&state, &contract_id, from).await?;
    let new = load_spec(&state, &contract_id, to).await?;
    // Both are Some: load_spec rejects an unparseable version above.
    let diff = SpecDiff::between(old.parsed.as_ref().unwrap(), new.parsed.as_ref().unwrap());

    Ok(Json(json!({
        "contract_id": contract_id,
        "from": from,
        "to": to,
        "diff": diff.to_json(),
    })))
}

/// One version's parsed interface, from the cache (versions are immutable, so
/// this is a pure hit after the first read).
async fn load_spec(
    state: &AppState,
    contract_id: &str,
    version: i32,
) -> ApiResult<Arc<CachedSpec>> {
    let spec = state
        .specs
        .at_version(&state.pool, contract_id, version)
        .await?;
    if spec.parsed.is_none() {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "stored spec section for version {version} could not be parsed"
        )));
    }
    Ok(spec)
}

#[derive(Deserialize)]
pub struct StateQuery {
    /// How many versions to return, newest first (1 = current state only).
    #[serde(default = "default_state_limit")]
    limit: i64,
}

fn default_state_limit() -> i64 {
    1
}

/// `GET /contracts/:id/state` — versioned snapshots of a contract's instance
/// storage, newest first. `limit=1` (default) is the current state.
pub async fn contract_state(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(q): Query<StateQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    let limit = q.limit.clamp(1, 200);
    let rows: Vec<(i64, SqlxJson<Value>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT ledger, storage, captured_at
         FROM contract_state WHERE contract_id = $1
         ORDER BY ledger DESC LIMIT $2",
    )
    .bind(&contract_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Err(ApiError::not_found(
            "no state snapshots for this contract (state indexing may be disabled, \
             or the contract hasn't been active since it was enabled)",
        ));
    }

    let latest_ledger = rows[0].0;
    let etag = generate_etag(&format!("{}:{}", contract_id, latest_ledger));
    if check_if_none_match(&headers, &etag) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }

    let versions: Vec<Value> = rows
        .into_iter()
        .map(|(ledger, storage, captured_at)| {
            json!({ "ledger": ledger, "storage": storage.0, "captured_at": captured_at })
        })
        .collect();
    let mut response = Json(json!({
        "contract_id": contract_id,
        "count": versions.len(),
        "versions": versions,
    })).into_response();
    response.headers_mut().insert(header::ETAG, etag.parse().unwrap());
    Ok(response)
}

#[derive(Deserialize)]
pub struct DataQuery {
    /// Filter to a discovery label, e.g. `balance`.
    label: Option<String>,
    /// Max keys to return (latest value of each), default 100.
    #[serde(default = "default_data_limit")]
    limit: i64,
}

fn default_data_limit() -> i64 {
    100
}

/// One `contract_data` row as selected below: (key_hash, key, durability,
/// ledger, value, label, captured_at).
type DataRow = (
    String,
    SqlxJson<Value>,
    String,
    i64,
    SqlxJson<Value>,
    Option<String>,
    DateTime<Utc>,
);

/// `GET /contracts/:id/data` — the current value of every *per-key* entry
/// snapshotted for this contract (e.g. every tracked holder balance), one row
/// per key (its latest snapshot). Requires the indexer's key indexing.
pub async fn contract_data(
    State(state): State<AppState>,
    Path(contract_id): Path<String>,
    Query(q): Query<DataQuery>,
) -> ApiResult<Json<Value>> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    let limit = q.limit.clamp(1, 1000);
    // DISTINCT ON gives the newest row per key_hash; the outer query orders and
    // bounds the set of keys returned.
    let rows: Vec<DataRow> = sqlx::query_as(
        "SELECT key_hash, key, durability, ledger, value, label, captured_at FROM (
                 SELECT DISTINCT ON (key_hash)
                        key_hash, key, durability, ledger, value, label, captured_at
                 FROM contract_data
                 WHERE contract_id = $1 AND ($2::text IS NULL OR label = $2)
                 ORDER BY key_hash, ledger DESC
             ) latest
             ORDER BY ledger DESC
             LIMIT $3",
    )
    .bind(&contract_id)
    .bind(&q.label)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Err(ApiError::not_found(
            "no per-key data snapshots for this contract (key indexing may be disabled, \
             or no tracked keys have been active since it was enabled)",
        ));
    }

    let keys: Vec<Value> = rows
        .into_iter()
        .map(
            |(key_hash, key, durability, ledger, value, label, captured_at)| {
                json!({
                    "key_hash": key_hash,
                    "key": key.0,
                    "durability": durability,
                    "ledger": ledger,
                    "value": value.0,
                    "label": label,
                    "captured_at": captured_at,
                })
            },
        )
        .collect();
    Ok(Json(json!({
        "contract_id": contract_id,
        "count": keys.len(),
        "keys": keys,
    })))
}

#[derive(Deserialize)]
pub struct DataHistoryQuery {
    /// How many versions to return, newest first.
    #[serde(default = "default_state_limit")]
    limit: i64,
}

/// `GET /contracts/:id/data/:key_hash` — the version history of a single
/// per-key entry (e.g. one holder's balance over time), newest first.
pub async fn contract_data_key(
    State(state): State<AppState>,
    Path((contract_id, key_hash)): Path<(String, String)>,
    Query(q): Query<DataHistoryQuery>,
) -> ApiResult<Json<Value>> {
    if !lumenqraph_core::is_valid_contract_id(&contract_id) {
        return Err(ApiError::bad_request("invalid contract id"));
    }
    let limit = q.limit.clamp(1, 500);
    // (key, durability, ledger, value, label, captured_at)
    type HistRow = (
        SqlxJson<Value>,
        String,
        i64,
        SqlxJson<Value>,
        Option<String>,
        DateTime<Utc>,
    );
    let rows: Vec<HistRow> = sqlx::query_as(
        "SELECT key, durability, ledger, value, label, captured_at
             FROM contract_data
             WHERE contract_id = $1 AND key_hash = $2
             ORDER BY ledger DESC LIMIT $3",
    )
    .bind(&contract_id)
    .bind(&key_hash)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    if rows.is_empty() {
        return Err(ApiError::not_found("no data snapshots for this key"));
    }

    // Key and durability are constant across a key's history; take them once.
    let key = rows[0].0 .0.clone();
    let durability = rows[0].1.clone();
    let label = rows[0].4.clone();
    let versions: Vec<Value> = rows
        .into_iter()
        .map(|(_, _, ledger, value, _, captured_at)| {
            json!({ "ledger": ledger, "value": value.0, "captured_at": captured_at })
        })
        .collect();
    Ok(Json(json!({
        "contract_id": contract_id,
        "key_hash": key_hash,
        "key": key,
        "durability": durability,
        "label": label,
        "count": versions.len(),
        "versions": versions,
    })))
}
