use crate::{AppState, Claims};
use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::{header, HeaderMap, Request};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use jsonwebtoken::{decode, errors::ErrorKind, DecodingKey, Validation};
use serde_json::json;
use std::sync::Arc;

pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let refresh_token_path = state.refresh_token_path.lock().await.clone();

    match token {
        Some(token) => {
            let validation = Validation::default();
            let key = DecodingKey::from_secret(state.jwt_secret.lock().await.as_bytes());
            match decode::<Claims>(token, &key, &validation) {
                Ok(_) => {
                    // valid token continue to handler
                    next.run(req).await
                }
                Err(err) => match *err.kind() {
                    ErrorKind::ExpiredSignature => {
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            header::WWW_AUTHENTICATE,
                            header::HeaderValue::from_str(&format!(
                                "Bearer error=\"invalid_token\", error_description=\"The access token expired\", refresh_url=\"{}\"",
                                refresh_token_path
                            )).unwrap()
                        );

                        (
                            StatusCode::UNAUTHORIZED,
                            headers,
                            Json(json!({
                                "error": "token_expired",
                                "message": "Your token has expired. Please refresh the token.",
                                "refresh_url": refresh_token_path
                            })),
                        )
                            .into_response()
                    }
                    _ => {
                        // other jwt error
                        let body = Json(json!({
                            "error": "invalid_token",
                            "message": "The provided token is invalid."
                        }));
                        (StatusCode::UNAUTHORIZED, body).into_response()
                    }
                },
            }
        }
        None => {
            // No token provided
            let body = Json(json!({
                "error": "missing_token",
                "message": "Authorization token is missing."
            }));
            (StatusCode::UNAUTHORIZED, body).into_response()
        }
    }
}
