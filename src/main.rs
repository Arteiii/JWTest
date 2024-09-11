mod middleware;
mod routes;

use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::{Pool, Row, Sqlite};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
    jwt_secret: Arc<Mutex<String>>,
    refresh_token_path: Arc<Mutex<String>>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize,
    sub: String,
}

fn generate_session_token(secret: &str, sub: &str) -> String {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(600)) // 10 mins
        .expect("valid timestamp")
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("valid duration")
        .as_secs() as usize;

    let claims = Claims {
        exp: expiration,
        sub: sub.to_owned(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

async fn generate_refresh_token(pool: &Pool<Sqlite>, user_id: &str) -> String {
    let refresh_token = Uuid::new_v4().to_string();

    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO refresh_tokens (user_id, token) VALUES (?, ?)")
        .bind(user_id)
        .bind(&refresh_token)
        .execute(pool)
        .await
        .unwrap();

    refresh_token
}

async fn validate_refresh_token(pool: &Pool<Sqlite>, user_id: &str, token: &str) -> bool {
    tracing::debug!("looking for userid: {} with token: {}", user_id, token);

    let row = sqlx::query("SELECT token FROM refresh_tokens WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap();

    if let Some(row) = row {
        let stored_token: String = row.get("token");
        tracing::debug!("token {:?}", stored_token);
        return stored_token == token;
    }

    tracing::debug!("nothing found!!");

    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let env_filter = if let Ok(env) = std::env::var("JWTest_LOG") {
        EnvFilter::new(env)
    } else if cfg!(debug_assertions) {
        EnvFilter::new(tracing::Level::DEBUG.to_string())
    } else {
        EnvFilter::new(tracing::Level::INFO.to_string())
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(env_filter)
        .init();

    let pool: Pool<Sqlite> = SqlitePool::connect("sqlite://sqlite.db").await?;

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            user_id TEXT PRIMARY KEY,
            token TEXT NOT NULL
        );
        ",
    )
    .execute(&pool)
    .await
    .unwrap();

    let shared_state = Arc::new(AppState {
        db: pool,
        // todo: update token
        jwt_secret: Arc::new(Mutex::new(
            "668cd8bd752013bbeee803bc330ee2f632022a637e70057588280d76aec02316".to_string(),
        )),
        refresh_token_path: Arc::new(Mutex::new("/refresh".to_string())),
    });

    let origins = [
        "http://example.com".parse().unwrap(),
        "http://api.example.com".parse().unwrap(),
    ];

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    axum::serve(
        listener,
        routes::configure_routes(shared_state.clone(), origins).await,
    )
    .await
    .expect("Failed to run Axum server");

    Ok(())
}
