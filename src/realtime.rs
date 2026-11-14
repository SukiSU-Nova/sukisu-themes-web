//! Server-sent real-time events for the console and the user center.
//!
//! The project intentionally has no Redis dependency: the service is a single
//! process, so a Tokio broadcast channel is enough. Browser clients keep a
//! WebSocket open for DM/announcement notifications and still fall back to the
//! existing polling if the socket cannot be established.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

use crate::accounts::SessionInfo;
use crate::api::AppState;

pub fn admin_router() -> Router<AppState> {
    Router::new().route("/events", get(admin_events))
}

pub fn account_router() -> Router<AppState> {
    Router::new().route("/events", get(account_events))
}

pub fn publish(state: &AppState, event: Value) {
    let _ = state.events.send(event);
}

async fn admin_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(_session): Extension<SessionInfo>,
) -> Response {
    ws.on_upgrade(move |socket| run_socket(state, socket, Audience::Admin, None))
}

async fn account_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(session): Extension<SessionInfo>,
) -> Response {
    let user_id = session.user_id;
    ws.on_upgrade(move |socket| run_socket(state, socket, Audience::User, Some(user_id)))
}

#[derive(Clone, Copy)]
enum Audience {
    Admin,
    User,
}

fn event_allowed(event: &Value, audience: Audience, user_id: Option<&str>) -> bool {
    match event.get("audience").and_then(Value::as_str) {
        Some("admin") => matches!(audience, Audience::Admin),
        Some("user") => {
            matches!(audience, Audience::User)
                && user_id.is_some()
                && event.get("userId").and_then(Value::as_str) == user_id
        }
        Some("all") => true,
        // Events without an explicit audience are console-only, never leak
        // account data to a user socket.
        _ => matches!(audience, Audience::Admin),
    }
}

async fn run_socket(
    state: AppState,
    socket: WebSocket,
    audience: Audience,
    user_id: Option<String>,
) {
    let mut receiver = state.events.subscribe();
    let (mut sender, mut incoming) = socket.split();
    let mut heartbeat = interval(Duration::from_secs(25));
    heartbeat.tick().await;
    let _ = sender
        .send(Message::Text(
            r#"{"type":"hello","ok":true}"#.to_string().into(),
        ))
        .await;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if sender.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
            message = incoming.next() => {
                match message {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            event = receiver.recv() => {
                match event {
                    Ok(event) => {
                        if event_allowed(&event, audience, user_id.as_deref()) {
                            if sender
                                .send(Message::Text(event.to_string().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
