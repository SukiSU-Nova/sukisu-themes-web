//! One site-wide announcement edited from the console settings page.
//!
//! The announcement carries a monotonically increasing version. Each user has
//! at most one read marker per version, so editing the text brings the dialog
//! back exactly once for everyone who has not read the new version yet.

use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::{json, Value};

use crate::accounts::{self, SessionInfo};
use crate::api::{json_body, ApiError, AppState};
use crate::util::now_iso;

type ApiResult<T> = Result<T, ApiError>;

const MAX_CONTENT: usize = 5000;

pub fn admin_router() -> Router<AppState> {
    Router::new().route("/announcement", get(admin_get).post(admin_save))
}

pub fn account_router() -> Router<AppState> {
    Router::new()
        .route("/announcement", get(account_get))
        .route("/announcement/read", post(account_read))
}

async fn read_state(state: &AppState) -> ApiResult<(String, i64, String)> {
    state
        .db
        .call(|conn| {
            let row = conn.query_row(
                "SELECT content, version, updated_at FROM social.site_announcement WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            );
            use rusqlite::OptionalExtension;
            Ok(row.optional()?.unwrap_or_else(|| (String::new(), 0, String::new())))
        })
        .await
        .map_err(ApiError::internal)
}

async fn admin_get(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let (content, version, updated_at) = read_state(&state).await?;
    Ok(Json(json!({
        "ok": true,
        "content": content,
        "version": version,
        "updatedAt": updated_at,
    })))
}

async fn admin_save(
    State(state): State<AppState>,
    Extension(actor): Extension<SessionInfo>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let value = json_body(body).await?;
    let content = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if content.chars().count() > MAX_CONTENT {
        return Err(ApiError::bad(format!("公告不能超过 {MAX_CONTENT} 字")));
    }
    let (old_content, version, _) = read_state(&state).await?;
    let changed = content != old_content;
    let next_version = if changed { version + 1 } else { version };
    let now = now_iso();
    let saved_content = content.clone();
    let saved_at = now.clone();
    state
        .db
        .call_write(move |conn| {
            conn.execute(
                "INSERT INTO social.site_announcement(id, content, version, updated_at)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    content = excluded.content,
                    version = excluded.version,
                    updated_at = excluded.updated_at",
                rusqlite::params![saved_content, next_version, saved_at],
            )?;
            Ok(())
        })
        .await
        .map_err(ApiError::internal)?;
    if changed {
        crate::realtime::publish(
            &state,
            serde_json::json!({
                "type": "announcement",
                "audience": "all",
                "version": next_version,
            }),
        );
        if let Err(error) = accounts::audit(
            &state.db,
            Some(&actor.user_id),
            "announcement.update",
            Some("site"),
            Some("announcement"),
            Some(&format!("version {next_version}")),
        )
        .await
        {
            tracing::warn!(?error, "failed to audit announcement update");
        }
    }
    Ok(Json(json!({
        "ok": true,
        "content": content,
        "version": next_version,
        "changed": changed,
        "updatedAt": now,
    })))
}

async fn account_get(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> ApiResult<Json<Value>> {
    let (content, version, updated_at) = read_state(&state).await?;
    let user_id = session.user_id.clone();
    let read = if content.is_empty() || version <= 0 {
        true
    } else {
        state
            .db
            .call(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM social.announcement_reads
                      WHERE user_id = ?1 AND version = ?2",
                    rusqlite::params![user_id, version],
                    |row| row.get(0),
                )?;
                Ok(count > 0)
            })
            .await
            .map_err(ApiError::internal)?
    };
    Ok(Json(json!({
        "ok": true,
        "content": content,
        "version": version,
        "updatedAt": updated_at,
        "unread": !read,
    })))
}

async fn account_read(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> ApiResult<Json<Value>> {
    let (_, version, _) = read_state(&state).await?;
    let user_id = session.user_id.clone();
    let now = now_iso();
    state
        .db
        .call_write(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO social.announcement_reads(user_id, version, read_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![user_id, version, now],
            )?;
            Ok(())
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"ok": true, "version": version})))
}
