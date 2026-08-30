//! Webhook subscription management. Consumers register a URL (+ optional
//! contract/event filters) and receive an HMAC-signing `secret` once, at
//! creation. The `lumenqraph-webhooks` service does the actual delivery.

use axum::extract::{Path, Query, State};
use axum::Json;
use lumenqraph_core::WebhookSubscription;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use sqlx::PgPool;
use tracing::warn;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::url_validation;

async fn log_webhook_action(
    pool: &PgPool,
    action_type: &str,
    resource_id: &str,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_log (key_hash_prefix, route, http_method, status_code, action_type, resource_id)
         VALUES ('webhook', '/webhooks', 'MUTATION', 200, $1, $2)"
    )
    .bind(action_type)
    .bind(resource_id)
    .execute(pool)
    .await
    {
        warn!(error = %e, "failed to log webhook action");
    }
}

#[derive(Deserialize)]
pub struct CreateWebhook {
    url: String,
    /// `"event"` (default) or `"upgrade"`. Defaulting preserves the behaviour of
    /// every caller written before upgrade subscriptions existed.
    #[serde(default = "default_kind")]
    kind: String,
    contract_id: Option<String>,
    event_name: Option<String>,
    /// Optional backfill: "last N", a ledger number, or a timestamp (ISO-8601).
    /// Defaults to current watermark (no backfill).
    #[serde(default)]
    since: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateWebhook {
    /// Toggle active/paused state of the subscription
    active: Option<bool>,
    /// Update contract filter
    contract_id: Option<String>,
    /// Update event name filter
    event_name: Option<String>,
}

fn default_kind() -> String {
    "event".to_string()
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub async fn create_webhook(
    State(state): State<AppState>,
    Json(body): Json<CreateWebhook>,
) -> ApiResult<Json<WebhookSubscription>> {
    url_validation::validate_webhook_url(&body.url)
        .map_err(|e| ApiError::bad_request(format!("invalid webhook url: {}", e)))?;

    if !matches!(body.kind.as_str(), "event" | "upgrade") {
        return Err(ApiError::bad_request(format!(
            "unknown kind `{}`; expected `event` or `upgrade`",
            body.kind
        )));
    }
    if body.kind == "upgrade" && body.event_name.is_some() {
        return Err(ApiError::bad_request(
            "event_name does not apply to an `upgrade` subscription; \
             use contract_id to watch one contract, or omit it to watch all",
        ));
    }
    let secret = random_secret();

    let starting_seq = if let Some(ref since) = body.since {
        calculate_starting_seq(&state.pool, since).await?
    } else {
        0
    };

    let encryption_key = std::env::var("WEBHOOK_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "default-key-for-testing".to_string());

    let sub: WebhookSubscription = sqlx::query_as(
        "INSERT INTO webhook_subscriptions (url, kind, contract_id, event_name, secret, encrypted_secret, starting_seq)
         VALUES ($1, $2, $3, $4, '[encrypted]', pgp_sym_encrypt($5, $6), $7)
         RETURNING id, url, kind, contract_id, event_name, '[encrypted]' as secret, active, created_at",
    )
    .bind(&body.url)
    .bind(&body.kind)
    .bind(&body.contract_id)
    .bind(&body.event_name)
    .bind(&secret)
    .bind(&encryption_key)
    .bind(starting_seq)
    .fetch_one(&state.pool)
    .await?;

    log_webhook_action(&state.pool, "webhook_create", &sub.id.to_string()).await;
    
    // Return the secret in the response (this is the only time it's exposed)
    let mut response = serde_json::to_value(&sub)?;
    if let Some(obj) = response.as_object_mut() {
        obj.insert("secret".to_string(), serde_json::Value::String(secret));
    }
    
    Ok(Json(serde_json::from_value(response)?))
}

async fn calculate_starting_seq(pool: &sqlx::PgPool, since: &str) -> ApiResult<i64> {
    if since.starts_with("last ") {
        let count_str = since.strip_prefix("last ").unwrap_or("0");
        let count: i64 = count_str.parse()
            .map_err(|_| ApiError::bad_request("invalid 'last N' format; expected 'last <number>'"))?;
        let current_max: i64 = sqlx::query_scalar("SELECT COALESCE(max(seq), 0) FROM events")
            .fetch_one(pool)
            .await?;
        Ok((current_max - count).max(0))
    } else if let Ok(ledger) = since.parse::<i64>() {
        let seq: Option<i64> = sqlx::query_scalar("SELECT min(seq) FROM events WHERE ledger >= $1")
            .bind(ledger)
            .fetch_optional(pool)
            .await?
            .flatten();
        Ok(seq.unwrap_or(0))
    } else {
        let ts = chrono::DateTime::parse_from_rfc3339(since)
            .map_err(|_| ApiError::bad_request("invalid timestamp format; expected ISO-8601"))?
            .with_timezone(&chrono::Utc);
        let seq: Option<i64> = sqlx::query_scalar("SELECT min(seq) FROM events WHERE ledger_closed_at >= $1")
            .bind(ts)
            .fetch_optional(pool)
            .await?
            .flatten();
        Ok(seq.unwrap_or(0))
    }
}

/// (id, url, kind, contract_id, event_name, active, created_at, auto_disabled_at, auto_disabled_reason)
type WebhookListRow = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
);

/// List subscriptions without exposing their secrets.
pub async fn list_webhooks(State(state): State<AppState>) -> ApiResult<Json<Vec<Value>>> {
    let rows: Vec<WebhookListRow> = sqlx::query_as(
        "SELECT id, url, kind, contract_id, event_name, active, created_at, auto_disabled_at, auto_disabled_reason
             FROM webhook_subscriptions ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    let out = rows
        .into_iter()
        .map(
            |(id, url, kind, contract_id, event_name, active, created_at, auto_disabled_at, auto_disabled_reason)| {
                json!({
                    "id": id,
                    "url": url,
                    "kind": kind,
                    "contract_id": contract_id,
                    "event_name": event_name,
                    "active": active,
                    "created_at": created_at,
                    "auto_disabled_at": auto_disabled_at,
                    "auto_disabled_reason": auto_disabled_reason,
                })
            },
        )
        .collect();
    Ok(Json(out))
}

pub async fn update_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateWebhook>,
) -> ApiResult<Json<Value>> {
    // Check that at least one field is being updated
    if body.active.is_none() && body.contract_id.is_none() && body.event_name.is_none() {
        return Err(ApiError::bad_request("no fields to update"));
    }

    // Validate filters if updating them
    if let Some(ref contract_id) = body.contract_id {
        if contract_id.is_empty() {
            return Err(ApiError::bad_request("contract_id cannot be empty"));
        }
    }

    // Get current subscription
    let current: (String, bool, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT kind, active, contract_id, event_name FROM webhook_subscriptions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("subscription not found"))?;

    let (kind, current_active, current_contract_id, current_event_name) = current;

    // Use current values as defaults if not provided in update
    let active = body.active.unwrap_or(current_active);
    let contract_id = body.contract_id.or(current_contract_id);
    let event_name = body.event_name.or(current_event_name);

    // Validate: event_name filter doesn't apply to upgrade subscriptions
    if kind == "upgrade" && event_name.is_some() {
        return Err(ApiError::bad_request(
            "event_name does not apply to an `upgrade` subscription; \
             use contract_id to watch one contract, or omit it to watch all",
        ));
    }

    // Update the subscription
    let sub: WebhookListRow = sqlx::query_as(
        "UPDATE webhook_subscriptions
         SET active = $2, contract_id = $3, event_name = $4
         WHERE id = $1
         RETURNING id, url, kind, contract_id, event_name, active, created_at, auto_disabled_at, auto_disabled_reason",
    )
    .bind(id)
    .bind(active)
    .bind(&contract_id)
    .bind(&event_name)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("subscription not found"))?;

    let (id, url, kind, contract_id, event_name, active, created_at, auto_disabled_at, auto_disabled_reason) = sub;
    log_webhook_action(&state.pool, "webhook_update", &id.to_string()).await;
    Ok(Json(json!({
        "id": id,
        "url": url,
        "kind": kind,
        "contract_id": contract_id,
        "event_name": event_name,
        "active": active,
        "created_at": created_at,
        "auto_disabled_at": auto_disabled_at,
        "auto_disabled_reason": auto_disabled_reason,
    })))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let affected = sqlx::query("DELETE FROM webhook_subscriptions WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(ApiError::not_found("subscription not found"));
    }
    log_webhook_action(&state.pool, "webhook_delete", &id.to_string()).await;
    Ok(Json(json!({ "deleted": id })))
}

/// Delivery history row for a webhook subscription.
type DeliveryRow = (
    i64,                                    // id
    String,                                 // status
    i32,                                    // attempts
    Option<String>,                         // last_error
    Option<chrono::DateTime<chrono::Utc>>, // delivered_at
    chrono::DateTime<chrono::Utc>,         // created_at
);

#[derive(Deserialize)]
pub struct DeliveriesQuery {
    /// Maximum number of deliveries to return (default 50, max 500).
    #[serde(default = "default_deliveries_limit")]
    limit: i64,
    /// Number of rows to skip for offset pagination (default 0).
    #[serde(default)]
    offset: i64,
}

fn default_deliveries_limit() -> i64 {
    50
}

pub async fn list_webhook_deliveries(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult<Json<Value>> {
    // Verify subscription exists
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM webhook_subscriptions WHERE id = $1)")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;

    if !exists {
        return Err(ApiError::not_found("subscription not found"));
    }

    let limit = q.limit.clamp(1, 500);
    let offset = q.offset.max(0);

    // Fetch total count first for pagination metadata.
    let total_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE subscription_id = $1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    // Fetch the requested page of deliveries.
    let deliveries: Vec<DeliveryRow> = sqlx::query_as(
        "SELECT id, status, attempts, last_error, delivered_at, created_at
         FROM webhook_deliveries
         WHERE subscription_id = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    // Fetch summary counts
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           COUNT(*) FILTER (WHERE status = 'delivered') as delivered_count,
           COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
           COUNT(*) FILTER (WHERE status = 'pending') as pending_count
         FROM webhook_deliveries
         WHERE subscription_id = $1",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    let has_more = offset + limit < total_count;

    let delivery_list = deliveries
        .into_iter()
        .map(|(id, status, attempts, last_error, delivered_at, created_at)| {
            json!({
                "id": id,
                "status": status,
                "attempts": attempts,
                "last_error": last_error,
                "delivered_at": delivered_at,
                "created_at": created_at,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "deliveries": delivery_list,
        "total_count": total_count,
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
        "summary": {
            "delivered": counts.0,
            "failed": counts.1,
            "pending": counts.2,
        }
    })))
}

#[derive(Deserialize)]
pub struct RedriveeQuery {
    since: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn redrive_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<RedriveeQuery>,
) -> ApiResult<Json<Value>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM webhook_subscriptions WHERE id = $1)"
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    if !exists {
        return Err(ApiError::not_found("subscription not found"));
    }

    let affected = if let Some(since) = query.since {
        sqlx::query(
            "UPDATE webhook_deliveries
             SET status = 'pending', attempts = 0, next_attempt_at = now(), last_error = NULL
             WHERE subscription_id = $1 AND status = 'failed' AND created_at >= $2"
        )
        .bind(id)
        .bind(since)
        .execute(&state.pool)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE webhook_deliveries
             SET status = 'pending', attempts = 0, next_attempt_at = now(), last_error = NULL
             WHERE subscription_id = $1 AND status = 'failed'"
        )
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected()
    };

    Ok(Json(json!({
        "redriven": affected
    })))
}

/// `POST /webhooks/:id/rotate-secret`
///
/// Generates a new HMAC signing secret for the subscription and returns it
/// **once** (it is never retrievable again). The previous secret remains valid
/// for a configurable grace period (`WEBHOOK_SECRET_GRACE_SECS`, default 300 s)
/// so consumers can update their configuration without a gap in verified
/// deliveries. After the grace period the old secret is discarded.
///
/// This operation does **not** reset the delivery watermark or cause any
/// deliveries to be replayed — subscription history is fully preserved.
pub async fn rotate_webhook_secret(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    // Verify the subscription exists.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM webhook_subscriptions WHERE id = $1)")
            .bind(id)
            .fetch_one(&state.pool)
            .await?;
    if !exists {
        return Err(ApiError::not_found("subscription not found"));
    }

    let new_secret = random_secret();
    let encryption_key = std::env::var("WEBHOOK_ENCRYPTION_KEY")
        .unwrap_or_else(|_| "default-key-for-testing".to_string());

    // Grace period: how long (seconds) the old secret stays valid alongside the new one.
    let grace_secs: i64 = std::env::var("WEBHOOK_SECRET_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    // Store the new secret and move the current secret into `previous_encrypted_secret`
    // with an expiry timestamp. The delivery service validates against both secrets
    // until `previous_secret_expires_at` passes.
    sqlx::query(
        "UPDATE webhook_subscriptions
         SET previous_encrypted_secret   = encrypted_secret,
             previous_secret_expires_at  = now() + ($1 * interval '1 second'),
             encrypted_secret            = pgp_sym_encrypt($2, $3)
         WHERE id = $4",
    )
    .bind(grace_secs)
    .bind(&new_secret)
    .bind(&encryption_key)
    .bind(id)
    .execute(&state.pool)
    .await?;

    log_webhook_action(&state.pool, "webhook_rotate_secret", &id.to_string()).await;

    Ok(Json(serde_json::json!({
        "id": id,
        "secret": new_secret,
        "previous_secret_valid_until": chrono::Utc::now()
            + chrono::Duration::seconds(grace_secs),
        "message": "Store this secret immediately — it will not be shown again.",
    })))
}

pub async fn reenable_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let affected = sqlx::query(
        "UPDATE webhook_subscriptions
         SET active = true, auto_disabled_at = NULL, auto_disabled_reason = NULL, consecutive_failures = 0
         WHERE id = $1 AND auto_disabled_at IS NOT NULL"
    )
    .bind(id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(ApiError::bad_request("subscription not found or not auto-disabled"));
    }

    Ok(Json(json!({
        "reenabled": true
    })))
}
