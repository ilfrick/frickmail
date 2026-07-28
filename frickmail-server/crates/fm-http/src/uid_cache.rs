use std::{collections::HashSet, time::Duration};

use deadpool_redis::{redis::cmd, Pool};
use fm_imap::LegacyMessageListUidCache;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::time::timeout;
use tracing::warn;

const CACHE_OPERATION_TIMEOUT: Duration = Duration::from_millis(750);
const CACHE_TTL_SECONDS: u64 = 43_200;
const MAX_CACHED_UIDS: usize = 100_000;
const MAX_CACHE_PAYLOAD_BYTES: usize = 1_200_000;
const BOUNDED_GET_SCRIPT: &str = "\
local value = redis.call('GET', KEYS[1]); \
if value and string.len(value) > tonumber(ARGV[1]) then return false end; \
return value";
type CacheError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub(crate) struct RedisLegacyMessageListUidCache {
    pool: Pool,
    account_prefix: String,
    fast_cache_index: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedUids {
    #[serde(rename = "FolderHash")]
    folder_hash: String,
    #[serde(rename = "Uids")]
    uids: Vec<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedThreadMap {
    #[serde(rename = "ThreadsUids")]
    threads_uids: Vec<Vec<u32>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedThreadUids {
    #[serde(rename = "ThreadsUids")]
    threads_uids: Vec<u32>,
}

impl RedisLegacyMessageListUidCache {
    pub(crate) fn new(pool: Pool, account_email: &str, fast_cache_index: String) -> Self {
        Self {
            pool,
            account_prefix: legacy_cache_account_prefix(account_email),
            fast_cache_index,
        }
    }

    async fn get_value(&self, backend_key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let mut connection = self.pool.get().await?;
        Ok(cmd("EVAL")
            .arg(BOUNDED_GET_SCRIPT)
            .arg(1)
            .arg(backend_key)
            .arg(MAX_CACHE_PAYLOAD_BYTES)
            .query_async(&mut connection)
            .await?)
    }

    async fn set_value(&self, backend_key: &str, payload: &[u8]) -> Result<(), CacheError> {
        let mut connection = self.pool.get().await?;
        Ok(cmd("SETEX")
            .arg(backend_key)
            .arg(CACHE_TTL_SECONDS)
            .arg(payload)
            .query_async(&mut connection)
            .await?)
    }

    async fn read_payload(&self, raw_key: &str, cache_kind: &str) -> Option<Vec<u8>> {
        let backend_key =
            legacy_cache_backend_key(&self.account_prefix, raw_key, &self.fast_cache_index);
        match timeout(CACHE_OPERATION_TIMEOUT, self.get_value(&backend_key)).await {
            Ok(Ok(Some(payload))) if payload.len() <= MAX_CACHE_PAYLOAD_BYTES => Some(payload),
            Ok(Ok(_)) => None,
            Ok(Err(error)) => {
                warn!(%error, cache_kind, "legacy message-list cache read failed");
                None
            }
            Err(_) => {
                warn!(cache_kind, "legacy message-list cache read timed out");
                None
            }
        }
    }

    async fn write_payload(&self, raw_key: &str, payload: &[u8], cache_kind: &str) {
        if payload.len() > MAX_CACHE_PAYLOAD_BYTES {
            return;
        }
        let backend_key =
            legacy_cache_backend_key(&self.account_prefix, raw_key, &self.fast_cache_index);
        match timeout(
            CACHE_OPERATION_TIMEOUT,
            self.set_value(&backend_key, payload),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!(%error, cache_kind, "legacy message-list cache write failed")
            }
            Err(_) => warn!(cache_kind, "legacy message-list cache write timed out"),
        }
    }
}

#[async_trait::async_trait]
impl LegacyMessageListUidCache for RedisLegacyMessageListUidCache {
    fn max_uid_entries(&self) -> usize {
        MAX_CACHED_UIDS
    }

    fn coordination_namespace(&self) -> String {
        format!("{}\0{}", self.account_prefix, self.fast_cache_index)
    }

    async fn get(&self, raw_key: &str, folder_hash: &str) -> Option<Vec<u32>> {
        let payload = self.read_payload(raw_key, "uids").await?;
        let cached = match serde_json::from_slice::<CachedUids>(&payload) {
            Ok(cached) if cached.folder_hash == folder_hash && valid_cached_uids(&cached.uids) => {
                cached
            }
            _ => return None,
        };
        Some(cached.uids)
    }

    async fn set(&self, raw_key: &str, folder_hash: &str, uids: &[u32]) {
        if !valid_cached_uids(uids) {
            return;
        }
        let Ok(payload) = serde_json::to_vec(&CachedUids {
            folder_hash: folder_hash.to_string(),
            uids: uids.to_vec(),
        }) else {
            return;
        };
        self.write_payload(raw_key, &payload, "uids").await;
    }

    async fn get_thread_map(&self, raw_key: &str) -> Option<Vec<Vec<u32>>> {
        let payload = self.read_payload(raw_key, "thread map").await?;
        let cached = serde_json::from_slice::<CachedThreadMap>(&payload).ok()?;
        valid_cached_threads(&cached.threads_uids).then_some(cached.threads_uids)
    }

    async fn set_thread_map(&self, raw_key: &str, threads: &[Vec<u32>]) {
        if !valid_cached_threads(threads) {
            return;
        }
        let Ok(payload) = serde_json::to_vec(&CachedThreadMap {
            threads_uids: threads.to_vec(),
        }) else {
            return;
        };
        self.write_payload(raw_key, &payload, "thread map").await;
    }

    async fn get_thread_uids(&self, raw_key: &str) -> Option<Vec<u32>> {
        let payload = self.read_payload(raw_key, "old thread UIDs").await?;
        let cached = serde_json::from_slice::<CachedThreadUids>(&payload).ok()?;
        valid_cached_uids(&cached.threads_uids).then_some(cached.threads_uids)
    }

    async fn set_thread_uids(&self, raw_key: &str, uids: &[u32]) {
        if !valid_cached_uids(uids) {
            return;
        }
        let Ok(payload) = serde_json::to_vec(&CachedThreadUids {
            threads_uids: uids.to_vec(),
        }) else {
            return;
        };
        self.write_payload(raw_key, &payload, "old thread UIDs")
            .await;
    }
}

fn valid_cached_uids(uids: &[u32]) -> bool {
    uids.len() <= MAX_CACHED_UIDS
        && uids.iter().all(|uid| *uid > 0)
        && uids.iter().copied().collect::<HashSet<_>>().len() == uids.len()
}

fn valid_cached_threads(threads: &[Vec<u32>]) -> bool {
    if threads.len() > MAX_CACHED_UIDS {
        return false;
    }
    let mut seen = HashSet::new();
    threads.iter().all(|thread| {
        !thread.is_empty()
            && thread
                .iter()
                .all(|uid| *uid > 0 && seen.len() < MAX_CACHED_UIDS && seen.insert(*uid))
    })
}

fn legacy_cache_account_prefix(account_email: &str) -> String {
    let mut account_email = account_email.as_bytes();
    while account_email
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | b'\0'))
    {
        account_email = &account_email[1..];
    }
    while account_email
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | b'\0'))
    {
        account_email = &account_email[..account_email.len() - 1];
    }
    while account_email
        .last()
        .is_some_and(|byte| matches!(byte, b'\\' | b'/'))
    {
        account_email = &account_email[..account_email.len() - 1];
    }
    if account_email.is_empty() {
        return String::new();
    }
    let sanitized = account_email
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || *byte == b'_' {
                char::from(*byte)
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{sanitized}/")
}

fn legacy_cache_backend_key(account_prefix: &str, raw_key: &str, fast_index: &str) -> String {
    let indexed_key = if fast_index.is_empty() {
        raw_key.to_string()
    } else {
        format!("{raw_key}\0{fast_index}")
    };
    let digest = Sha1::digest(indexed_key.as_bytes());
    format!("{account_prefix}{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::{
        legacy_cache_account_prefix, legacy_cache_backend_key, valid_cached_threads,
        valid_cached_uids, CachedThreadMap, CachedThreadUids, CachedUids,
        RedisLegacyMessageListUidCache, MAX_CACHED_UIDS,
    };
    use deadpool_redis::{redis::cmd, Config, Runtime};
    use fm_imap::LegacyMessageListUidCache;

    #[test]
    fn legacy_cache_key_matches_php_account_prefix_and_sha1_contract() {
        assert_eq!(
            legacy_cache_account_prefix(" Alice+tag@example.com/ "),
            "Alice_tag_example_com/"
        );
        assert_eq!(
            legacy_cache_account_prefix("ü@example.com"),
            "___example_com/"
        );
        assert_eq!(
            legacy_cache_backend_key(
                "Alice_tag_example_com/",
                "GetUIDS/REVERSE DATE/hash/INBOX/ALL",
                "v1"
            ),
            "Alice_tag_example_com/4650cadc63382ddce53dc0c7761c1f1e5b2d2145"
        );
    }

    #[test]
    fn cached_payload_uses_legacy_field_names() {
        let payload = serde_json::to_string(&CachedUids {
            folder_hash: "etag".to_string(),
            uids: vec![9, 4],
        })
        .unwrap();

        assert_eq!(payload, r#"{"FolderHash":"etag","Uids":[9,4]}"#);
        assert_eq!(
            serde_json::to_string(&CachedThreadMap {
                threads_uids: vec![vec![9, 4], vec![7]]
            })
            .unwrap(),
            r#"{"ThreadsUids":[[9,4],[7]]}"#
        );
        assert_eq!(
            serde_json::to_string(&CachedThreadUids {
                threads_uids: vec![4, 7]
            })
            .unwrap(),
            r#"{"ThreadsUids":[4,7]}"#
        );
    }

    #[test]
    fn cached_uids_are_bounded_positive_and_unique() {
        assert!(valid_cached_uids(&[9, 4]));
        assert!(!valid_cached_uids(&[9, 0]));
        assert!(!valid_cached_uids(&[9, 9]));
        assert!(!valid_cached_uids(&vec![1; MAX_CACHED_UIDS + 1]));
    }

    #[test]
    fn cached_threads_are_bounded_positive_nonempty_and_globally_unique() {
        assert!(valid_cached_threads(&[vec![9, 4], vec![7]]));
        assert!(valid_cached_threads(&[]));
        assert!(!valid_cached_threads(&[vec![]]));
        assert!(!valid_cached_threads(&[vec![9, 0]]));
        assert!(!valid_cached_threads(&[vec![9], vec![9]]));
        assert!(!valid_cached_threads(&[vec![1; MAX_CACHED_UIDS + 1]]));
    }

    #[tokio::test]
    async fn redis_cache_round_trip_when_test_server_is_configured() {
        let Ok(url) = std::env::var("FRICKMAIL_TEST_REDIS_URL") else {
            return;
        };
        let pool = Config::from_url(url)
            .create_pool(Some(Runtime::Tokio1))
            .unwrap();
        let raw_key = format!("GetUIDS//test/INBOX/ALL-{}", std::process::id());
        let account_prefix = legacy_cache_account_prefix("cache-test@example.com");
        let backend_key = legacy_cache_backend_key(&account_prefix, &raw_key, "test-v1");
        let cache = RedisLegacyMessageListUidCache::new(
            pool.clone(),
            "cache-test@example.com",
            "test-v1".to_string(),
        );

        cache.set(&raw_key, "etag-1", &[9, 4]).await;
        assert_eq!(cache.get(&raw_key, "etag-1").await, Some(vec![9, 4]));
        assert_eq!(cache.get(&raw_key, "stale-etag").await, None);

        let thread_map_key = format!("ThreadsMap/REFERENCES/ALL/test-etag-{}", std::process::id());
        cache
            .set_thread_map(&thread_map_key, &[vec![9, 4], vec![7]])
            .await;
        assert_eq!(
            cache.get_thread_map(&thread_map_key).await,
            Some(vec![vec![9, 4], vec![7]])
        );

        let thread_uids_key = format!("ThreadsOldUids/test-etag-{}/N", std::process::id());
        cache.set_thread_uids(&thread_uids_key, &[4, 7]).await;
        assert_eq!(
            cache.get_thread_uids(&thread_uids_key).await,
            Some(vec![4, 7])
        );

        let mut connection = pool.get().await.unwrap();
        let ttl: i64 = cmd("TTL")
            .arg(&backend_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((43_190..=43_200).contains(&ttl));
        let _: usize = cmd("DEL")
            .arg(backend_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        for raw_key in [&thread_map_key, &thread_uids_key] {
            let backend_key = legacy_cache_backend_key(&account_prefix, raw_key, "test-v1");
            let _: usize = cmd("DEL")
                .arg(backend_key)
                .query_async(&mut connection)
                .await
                .unwrap();
        }
    }
}
