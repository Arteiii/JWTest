use crate::{
    generate_refresh_token, generate_session_token, middleware::auth_middleware,
    validate_refresh_token, AppState,
};
use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderValue, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use serde::Deserialize;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use std::{sync::Arc, time::Duration};
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

pub async fn configure_routes(state: Arc<AppState>, origins: [HeaderValue; 2]) -> Router {
    Router::new()
        .route("/", get(index))
        .route(
            "/auth",
            get(auth_route).layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route("/register", get(request_token))
        .route(
            &state.refresh_token_path.clone().lock().await.clone(),
            get(refresh_token),
        )
        .with_state(state)
        .layer(TimeoutLayer::new(Duration::from_secs(90))) // abort request after 90sec
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_headers([AUTHORIZATION])
                .allow_methods([Method::GET, Method::POST, Method::PUT]),
        )
        .layer(TraceLayer::new_for_http())
}

async fn index() -> &'static str {
    "Welcome to the public index!"
}

async fn auth_route(State(_state): State<Arc<AppState>>) -> &'static str {
    "You are authorized to see this!"
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
    user_id: String,
}

async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> impl IntoResponse {
    let refresh_token = &payload.refresh_token;
    let user_id = &payload.user_id;

    let db: Pool<Sqlite> = state.db.clone();

    let is_valid = validate_refresh_token(&db, user_id, refresh_token).await;
    if !is_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_refresh_token",
                "message": "The provided refresh token is invalid."
            })),
        )
            .into_response();
    }

    let new_access_token = generate_refresh_token(&db, user_id).await;
    let new_session_token = generate_session_token(state.jwt_secret.lock().await.as_str(), user_id);

    (
        StatusCode::OK,
        Json(json!({"access_token": new_access_token, "session_token": new_session_token})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TokenRequest {
    user_id: String,
}

async fn request_token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenRequest>,
) -> impl IntoResponse {
    let db = state.db.clone();

    let new_access_token = generate_refresh_token(&db, &payload.user_id).await;

    (
        StatusCode::OK,
        Json(json!({"access_token": new_access_token})),
    )
        .into_response()
}
