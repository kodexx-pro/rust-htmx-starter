use std::{future::Future, time::Duration};

use anyhow::Context;
use serde::{Serialize, de::DeserializeOwned};
use sqlx::PgPool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheTtl {
    Missing,
    Persistent,
    Seconds(u64),
}

#[derive(Clone)]
pub struct PgCache {
    db: PgPool,
}

impl PgCache {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>> {
        let raw: Option<String> = sqlx::query_scalar("SELECT cache_get($1)")
            .bind(key)
            .fetch_one(&self.db)
            .await
            .context("Falha ao ler chave do cache no PostgreSQL")?;

        match raw {
            Some(json) => {
                let value = serde_json::from_str(&json)
                    .context("Falha ao desserializar JSON do cache no PostgreSQL")?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> anyhow::Result<()> {
        let json = serde_json::to_string(value)
            .context("Falha ao serializar valor JSON para o cache no PostgreSQL")?;
        let ttl_seconds = ttl.map(duration_to_ttl_seconds);

        sqlx::query("CALL cache_set($1, $2, $3)")
            .bind(key)
            .bind(json)
            .bind(ttl_seconds)
            .execute(&self.db)
            .await
            .context("Falha ao gravar chave no cache no PostgreSQL")?;

        Ok(())
    }

    pub async fn get_or_set<T, F, Fut>(
        &self,
        key: &str,
        ttl: Option<Duration>,
        loader: F,
    ) -> anyhow::Result<T>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        if let Ok(Some(cached)) = self.get::<T>(key).await {
            return Ok(cached);
        }

        let fresh = loader().await?;
        if let Err(err) = self.set(key, &fresh, ttl).await {
            tracing::warn!(cache_key = key, error = ?err, "Erro ao popular cache");
        }
        Ok(fresh)
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        sqlx::query("CALL cache_del($1)")
            .bind(key)
            .execute(&self.db)
            .await
            .context("Falha ao remover chave do cache no PostgreSQL")?;
        Ok(())
    }

    pub async fn delete_prefix(&self, prefix: &str) -> anyhow::Result<()> {
        sqlx::query("CALL cache_del_prefix($1)")
            .bind(prefix)
            .execute(&self.db)
            .await
            .context("Falha ao remover prefixo do cache no PostgreSQL")?;
        Ok(())
    }

    pub async fn ttl(&self, key: &str) -> anyhow::Result<CacheTtl> {
        let ttl: i64 = sqlx::query_scalar("SELECT cache_ttl($1)")
            .bind(key)
            .fetch_one(&self.db)
            .await
            .context("Falha ao consultar TTL do cache no PostgreSQL")?;

        Ok(match ttl {
            -2 => CacheTtl::Missing,
            -1 => CacheTtl::Persistent,
            secs => CacheTtl::Seconds(secs.max(0) as u64),
        })
    }

    pub async fn purge_expired(&self) -> anyhow::Result<i64> {
        let deleted: i64 = sqlx::query_scalar("CALL cache_purge_expired(0)")
            .fetch_one(&self.db)
            .await
            .context("Falha ao limpar entradas expiradas do cache")?;
        Ok(deleted)
    }

    pub async fn incr_with_ttl(&self, key: &str, ttl: Duration) -> anyhow::Result<i64> {
        let ttl_secs = duration_to_ttl_seconds(ttl).max(1);
        let count: i64 = sqlx::query_scalar("SELECT cache_incr($1, $2)")
            .bind(key)
            .bind(ttl_secs)
            .fetch_one(&self.db)
            .await
            .context("Falha ao incrementar contador atômico no cache")?;
        Ok(count)
    }
}
fn duration_to_ttl_seconds(ttl: Duration) -> i32 {
    if ttl.is_zero() {
        return 0;
    }
    let secs = ttl.as_secs().max(1);
    i32::try_from(secs).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn duration_conversion_preserves_zero_and_subsecond_positive_ttls() {
        assert_eq!(duration_to_ttl_seconds(Duration::ZERO), 0);
        assert_eq!(duration_to_ttl_seconds(Duration::from_millis(250)), 1);
        assert_eq!(duration_to_ttl_seconds(Duration::from_secs(300)), 300);
        assert_eq!(duration_to_ttl_seconds(Duration::MAX), i32::MAX);
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SamplePayload {
        role: String,
        count: u32,
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn unlogged_cache_enforces_expiry_and_procedures(pool: PgPool) -> anyhow::Result<()> {
        let cache = PgCache::new(pool.clone());

        let is_unlogged: String = sqlx::query_scalar(
            "SELECT relpersistence::text FROM pg_class WHERE relname = 'cache_entries'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(is_unlogged, "u");

        let payload = SamplePayload {
            role: "admin".into(),
            count: 7,
        };
        cache
            .set("session:abc", &payload, Some(Duration::from_secs(1)))
            .await?;

        assert_eq!(
            cache.get::<SamplePayload>("session:abc").await?,
            Some(payload.clone())
        );
        assert!(matches!(
            cache.ttl("session:abc").await?,
            CacheTtl::Seconds(0..=1)
        ));

        tokio::time::sleep(Duration::from_millis(1150)).await;

        // Expiração lazy na leitura + limpeza
        assert_eq!(cache.get::<SamplePayload>("session:abc").await?, None);
        assert_eq!(cache.ttl("session:abc").await?, CacheTtl::Missing);

        // Chave persistente + remoção por prefixo + purge em lote
        cache.set("user:1:prefs", &payload, None).await?;
        assert_eq!(cache.ttl("user:1:prefs").await?, CacheTtl::Persistent);
        cache.delete_prefix("user:1:").await?;
        assert_eq!(cache.get::<SamplePayload>("user:1:prefs").await?, None);

        cache
            .set("tmp:expired", &payload, Some(Duration::from_secs(1)))
            .await?;
        tokio::time::sleep(Duration::from_millis(1150)).await;
        assert_eq!(cache.purge_expired().await?, 1);

        // Contador atômico com janela fixa (rate limit)
        assert_eq!(
            cache
                .incr_with_ttl("rl:login:abc", Duration::from_secs(1))
                .await?,
            1
        );
        assert_eq!(
            cache
                .incr_with_ttl("rl:login:abc", Duration::from_secs(1))
                .await?,
            2
        );
        tokio::time::sleep(Duration::from_millis(1150)).await;
        assert_eq!(
            cache
                .incr_with_ttl("rl:login:abc", Duration::from_secs(1))
                .await?,
            1
        );

        Ok(())
    }
}
