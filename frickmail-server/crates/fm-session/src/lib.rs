use std::time::Duration;

use async_trait::async_trait;
use tower_sessions::{
    cookie::SameSite, Expiry as SessionExpiry, SessionManagerLayer, SessionStore,
};
use tower_sessions_redis_store::fred::interfaces::ClientLike;

pub use tower_sessions::{MemoryStore, Session};

use tower_sessions_redis_store::{fred::prelude::Pool, RedisStore};

pub const USER_SESSION_KEY: &str = "frickmail_user";
pub const CREDENTIAL_KEY_SESSION_KEY: &str = "frickmail_credential_key";
pub const SELECTED_ACCOUNT_SESSION_KEY: &str = "frickmail_selected_account";
pub const CONNECTION_TOKEN_SECRET_KEY: &str = "frickmail_connection_token_secret";
pub const CONNECTION_TOKEN_ACCOUNT_ID_KEY: &str = "frickmail_connection_token_account_id";

#[derive(Debug, Clone)]
pub enum AppSessionStore {
    Memory(MemoryStore),
    Redis(RedisStore<Pool>),
}

impl AppSessionStore {
    pub async fn redis(redis_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = tower_sessions_redis_store::fred::types::config::Config::from_url(redis_url)?;
        let pool =
            tower_sessions_redis_store::fred::prelude::Pool::new(config, None, None, None, 6)?;
        let connection = pool.connect();
        tokio::time::timeout(Duration::from_secs(5), pool.wait_for_connect())
            .await
            .map_err(|_| "timed out connecting to Redis session store")??;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!("Frickmail session Redis connection failed: {error}");
            }
        });
        Ok(Self::Redis(RedisStore::new(pool)))
    }
}

#[async_trait]
impl SessionStore for AppSessionStore {
    async fn create(
        &self,
        record: &mut tower_sessions::session::Record,
    ) -> tower_sessions::session_store::Result<()> {
        match self {
            Self::Memory(store) => store.create(record).await,
            Self::Redis(store) => store.create(record).await,
        }
    }

    async fn save(
        &self,
        record: &tower_sessions::session::Record,
    ) -> tower_sessions::session_store::Result<()> {
        match self {
            Self::Memory(store) => store.save(record).await,
            Self::Redis(store) => store.save(record).await,
        }
    }

    async fn load(
        &self,
        session_id: &tower_sessions::session::Id,
    ) -> tower_sessions::session_store::Result<Option<tower_sessions::session::Record>> {
        match self {
            Self::Memory(store) => store.load(session_id).await,
            Self::Redis(store) => store.load(session_id).await,
        }
    }

    async fn delete(
        &self,
        session_id: &tower_sessions::session::Id,
    ) -> tower_sessions::session_store::Result<()> {
        match self {
            Self::Memory(store) => store.delete(session_id).await,
            Self::Redis(store) => store.delete(session_id).await,
        }
    }
}

pub fn session_layer(store: AppSessionStore) -> SessionManagerLayer<AppSessionStore> {
    SessionManagerLayer::new(store)
        .with_name("FrickmailSession")
        .with_same_site(SameSite::Lax)
        .with_http_only(true)
        .with_expiry(SessionExpiry::OnInactivity(
            tower_sessions::cookie::time::Duration::hours(12),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    #[ignore = "requires a Redis server; run with --ignored and FRICKMAIL_SESSION_REDIS_URL"]
    async fn redis_store_persists_record_across_instances(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let redis_url = std::env::var("FRICKMAIL_SESSION_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379/15".to_owned());
        let writer = AppSessionStore::redis(&redis_url).await?;
        let reader = AppSessionStore::redis(&redis_url).await?;
        let mut record = tower_sessions::session::Record {
            id: tower_sessions::session::Id::default(),
            data: HashMap::from([("user_id".to_owned(), serde_json::json!(42))]),
            expiry_date: time::OffsetDateTime::now_utc() + time::Duration::minutes(10),
        };

        writer.create(&mut record).await?;

        let loaded = reader
            .load(&record.id)
            .await?
            .expect("session record survives a new store connection");
        assert_eq!(loaded.data, record.data);

        reader.delete(&record.id).await?;
        assert!(reader.load(&record.id).await?.is_none());

        Ok(())
    }
}
