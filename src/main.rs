mod masked_token;
mod middleware;
mod routes;

use crate::masked_token::MaskedToken;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::{Pool, Row, Sqlite};
use std::convert::Into;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::io;
use tokio::sync::Mutex;
use uuid::Uuid;

const JWT_SECRET: &str = env!("JWT_SECRET");

#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
    jwt_secret: Arc<MaskedToken>,
    refresh_token_path: Arc<Mutex<String>>,
}

impl AppState {
    async fn jwt_secret_bytes(&self) -> Vec<u8> {
        let jwt_secret = self.jwt_secret.as_ref();
        jwt_secret.as_ref().as_bytes().to_vec()
    }
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

    let jwt_token: MaskedToken = JWT_SECRET.into();

    tracing::info!("jwt_token: {}", jwt_token);

    let shared_state = Arc::new(AppState {
        db: pool,
        jwt_secret: Arc::new(jwt_token),
        refresh_token_path: Arc::new(Mutex::new("/refresh".to_string())),
    });

    let origins = [
        "http://example.com".parse().unwrap(),
        "http://api.example.com".parse().unwrap(),
    ];

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        Ok(listener) => listener,
        Err(err) => {
            if err.kind() == io::ErrorKind::AddrInUse {
                eprintln!("Error: The address is already in use. Please ensure no other process is using port 3000.");
            } else {
                eprintln!("Error: {}", err);
            }
            return Err(err.into());
        }
    };

    axum::serve(
        listener,
        routes::configure_routes(shared_state.clone(), origins).await,
    )
    .await
    .expect("Failed to run Axum server");

    Ok(())
}
