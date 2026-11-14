//! Private messages between a signed-in user and the console administrators.
//!
//! There is one thread per user. Admins see all threads, users only their own;
//! unread flags are tracked per side so the console bell and the user-center
//! "管理员私信" tab can both show a count.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::{json, Value};

use crate::accounts::{self, SessionInfo};
use crate::api::{json_body, ApiError, AppState};
use crate::util::{now_iso, random_hex};

type ApiResult<T> = Result<T, ApiError>;

const MAX_MESSAGE: usize = 2000;

pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/dm/conversations", get(admin_conversations))
        .route("/dm/unread", get(admin_unread))
        .route("/dm/{user}", get(admin_thread))
        .route("/dm/{user}/send", post(admin_send))
        .route("/dm/{user}/read", post(admin_read))
}

pub fn account_router() -> Router<AppState> {
    Router::new()
        .route("/dm", get(account_thread))
        .route("/dm/unread", get(account_unread))
        .route("/dm/send", post(account_send))
        .route("/dm/read", post(account_read))
}

fn clean_body(body: &str) -> ApiResult<String> {
    let body = body.trim();
    if body.is_empty() {
        return Err(ApiError::bad("消息不能为空"));
    }
    if body.chars().count() > MAX_MESSAGE {
        return Err(ApiError::bad(format!("消息不能超过 {MAX_MESSAGE} 字")));
    }
    Ok(body.to_string())
}

pub async fn admin_unread_count(state: &AppState) -> anyhow::Result<i64> {
    state
        .db
        .call(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM social.user_dm_messages
                  WHERE sender_role = 'user' AND read_by_admin = 0",
                [],
                |row| row.get(0),
            )?)
        })
        .await
}

async fn admin_unread(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    let unread = admin_unread_count(&state).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"ok": true, "unread": unread})))
}

async fn admin_conversations(
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, String, String, Option<String>, String, i64, Option<String>)> = state
        .db
        .call(|conn| {
            let mut statement = conn.prepare(
                "SELECT m.user_id,
                        COALESCE(u.username, ''),
                        COALESCE(u.display_name, ''),
                        u.avatar,
                        MAX(m.created_at),
                        SUM(CASE WHEN m.sender_role = 'user' AND m.read_by_admin = 0 THEN 1 ELSE 0 END),
                        (SELECT x.body FROM social.user_dm_messages x
                          WHERE x.user_id = m.user_id ORDER BY x.created_at DESC LIMIT 1)
                   FROM social.user_dm_messages m
                   LEFT JOIN users u ON u.id = m.user_id
                  GROUP BY m.user_id
                  ORDER BY MAX(m.created_at) DESC
                  LIMIT 300",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .map_err(ApiError::internal)?;
    let mut unread_total = 0i64;
    let conversations: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, display_name, avatar, last_at, unread, last_body)| {
            unread_total += unread;
            json!({
                "userId": user_id,
                "username": username,
                "displayName": display_name,
                "avatar": avatar,
                "lastAt": last_at,
                "lastBody": last_body.unwrap_or_default(),
                "unread": unread,
            })
        })
        .collect();
    Ok(Json(json!({
        "ok": true,
        "unreadTotal": unread_total,
        "conversations": conversations,
    })))
}

async fn admin_thread(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = load_user(&state, &user_id).await?;
    let messages = load_messages(&state, &user_id, true).await?;
    mark_read(&state, &user_id, true).await?;
    Ok(Json(json!({
        "ok": true,
        "user": user,
        "messages": messages,
    })))
}

async fn admin_send(
    State(state): State<AppState>,
    Extension(actor): Extension<SessionInfo>,
    Path(user_id): Path<String>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Value>> {
    let value = json_body(body).await?;
    let text = clean_body(value.get("body").and_then(Value::as_str).unwrap_or(""))?;
    if !crate::account_api::rate_allowed(&state, &format!("dm:admin:{}", actor.user_id), 60, 60) {
        return Err(ApiError::too_many("发送太频繁，请稍后再试"));
    }
    load_user(&state, &user_id).await?;
    let sender = actor.user_id.clone();
    let sender_name = if actor.display_name.trim().is_empty() {
        actor.username.clone()
    } else {
        actor.display_name.clone()
    };
    store_message(&state, &user_id, "admin", Some(&sender), &sender_name, &text).await?;
    let user_unread = user_unread_count(&state, &user_id).await.unwrap_or(0);
    crate::realtime::publish(
        &state,
        json!({
            "type": "dm",
            "audience": "user",
            "userId": user_id,
            "senderName": sender_name,
            "unread": user_unread,
            "body": text.chars().take(200).collect::<String>(),
            "createdAt": now_iso(),
        }),
    );
    crate::realtime::publish(
        &state,
        json!({
            "type": "dm-thread",
            "audience": "admin",
            "userId": user_id,
            "senderName": sender_name,
        }),
    );
    if let Err(error) = accounts::audit(
        &state.db,
        Some(&sender),
        "dm.send",
        Some("user"),
        Some(&user_id),
        Some(&text.chars().take(120).collect::<String>()),
    )
    .await
    {
        tracing::warn!(?error, "failed to audit direct message");
    }
    Ok(Json(json!({"ok": true})))
}

async fn admin_read(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    mark_read(&state, &user_id, true).await?;
    Ok(Json(json!({"ok": true})))
}

async fn account_unread(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> ApiResult<Json<Value>> {
    let user_id = session.user_id.clone();
    let unread: i64 = state
        .db
        .call(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM social.user_dm_messages
                  WHERE user_id = ?1 AND sender_role = 'admin' AND read_by_user = 0",
                [&user_id],
                |row| row.get(0),
            )?)
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({"ok": true, "unread": unread})))
}

async fn account_thread(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> ApiResult<Json<Value>> {
    let messages = load_messages(&state, &session.user_id, false).await?;
    mark_read(&state, &session.user_id, false).await?;
    Ok(Json(json!({"ok": true, "messages": messages})))
}

async fn account_send(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Value>> {
    let value = json_body(body).await?;
    let text = clean_body(value.get("body").and_then(Value::as_str).unwrap_or(""))?;
    if !crate::account_api::rate_allowed(&state, &format!("dm:user:{}", session.user_id), 10, 60) {
        return Err(ApiError::too_many("私信太频繁，每分钟最多发送 10 条"));
    }
    let sender_name = if session.display_name.trim().is_empty() {
        session.username.clone()
    } else {
        session.display_name.clone()
    };
    store_message(&state, &session.user_id, "user", Some(&session.user_id), &sender_name, &text).await?;
    let admin_unread = admin_unread_count(&state).await.unwrap_or(0);
    crate::realtime::publish(
        &state,
        json!({
            "type": "dm",
            "audience": "admin",
            "userId": session.user_id,
            "senderName": sender_name,
            "unread": admin_unread,
            "body": text.chars().take(200).collect::<String>(),
            "createdAt": now_iso(),
        }),
    );
    Ok(Json(json!({"ok": true})))
}

async fn account_read(
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> ApiResult<Json<Value>> {
    mark_read(&state, &session.user_id, false).await?;
    Ok(Json(json!({"ok": true})))
}

async fn store_message(
    state: &AppState,
    user_id: &str,
    role: &str,
    sender_id: Option<&str>,
    sender_name: &str,
    body: &str,
) -> ApiResult<()> {
    let id = format!("dm_{}", random_hex(12));
    let user_id = user_id.to_string();
    let role = role.to_string();
    let sender_id = sender_id.map(str::to_string);
    let sender_name = sender_name.to_string();
    let body = body.to_string();
    let now = now_iso();
    let (admin_read, user_read) = if role == "admin" { (1, 0) } else { (0, 1) };
    state
        .db
        .call_write(move |conn| {
            conn.execute(
                "INSERT INTO social.user_dm_messages
                    (id, user_id, sender_role, sender_id, sender_name, body, created_at, read_by_admin, read_by_user)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![id, user_id, role, sender_id, sender_name, body, now, admin_read, user_read],
            )?;
            Ok(())
        })
        .await
        .map_err(ApiError::internal)
}

pub async fn user_unread_count(state: &AppState, user_id: &str) -> anyhow::Result<i64> {
    let user_id = user_id.to_string();
    state
        .db
        .call(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM social.user_dm_messages
                  WHERE user_id = ?1 AND sender_role = 'admin' AND read_by_user = 0",
                [&user_id],
                |row| row.get(0),
            )?)
        })
        .await
}

async fn mark_read(state: &AppState, user_id: &str, by_admin: bool) -> ApiResult<()> {
    let user_id = user_id.to_string();
    state
        .db
        .call_write(move |conn| {
            if by_admin {
                conn.execute(
                    "UPDATE social.user_dm_messages SET read_by_admin = 1
                      WHERE user_id = ?1 AND sender_role = 'user' AND read_by_admin = 0",
                    [&user_id],
                )?;
            } else {
                conn.execute(
                    "UPDATE social.user_dm_messages SET read_by_user = 1
                      WHERE user_id = ?1 AND sender_role = 'admin' AND read_by_user = 0",
                    [&user_id],
                )?;
            }
            Ok(())
        })
        .await
        .map_err(ApiError::internal)
}

async fn load_user(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let id = user_id.to_string();
    let row = state
        .db
        .call(move |conn| {
            let row = conn.query_row(
                "SELECT id, username, display_name, avatar FROM users WHERE id = ?1",
                [&id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            );
            use rusqlite::OptionalExtension;
            Ok(row.optional()?)
        })
        .await
        .map_err(ApiError::internal)?;
    let Some((user_id, username, display_name, avatar)) = row else {
        return Err(ApiError::not_found("用户不存在"));
    };
    Ok(json!({"userId": user_id, "username": username, "displayName": display_name, "avatar": avatar}))
}

async fn load_messages(state: &AppState, user_id: &str, for_admin: bool) -> ApiResult<Vec<Value>> {
    let id = user_id.to_string();
    let rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        i64,
        i64,
    )> = state
        .db
        .call(move |conn| {
            let mut statement = conn.prepare(
                "SELECT m.id, m.sender_role,
                        COALESCE(NULLIF(m.sender_name, ''), u.display_name, u.username,
                                 CASE WHEN m.sender_role = 'admin' THEN '管理员' ELSE '' END),
                        m.sender_id, m.body, m.created_at, m.read_by_admin, m.read_by_user
                   FROM social.user_dm_messages m
                   LEFT JOIN users u ON u.id = m.sender_id
                  WHERE m.user_id = ?1
                  ORDER BY m.created_at ASC
                  LIMIT 500",
            )?;
            let rows = statement.query_map([&id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .map_err(ApiError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, role, sender_name, sender_id, body, created_at, read_by_admin, read_by_user)| {
            json!({
                "id": id,
                "role": role,
                "senderName": sender_name,
                "senderId": sender_id,
                "body": body,
                "createdAt": created_at,
                "read": if for_admin { read_by_admin != 0 } else { read_by_user != 0 },
            })
        })
        .collect())
}
