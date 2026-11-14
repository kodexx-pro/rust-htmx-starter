use std::time::Duration;

use anyhow::Context;
use askama::filters::{Html, escape};
use pgboss::{Client, Job};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction, types::Json};
use uuid::Uuid;

use crate::{i18n::Locale, mailer::ResendMailer};

pub const QUEUE_VERIFY_EMAIL: &str = "email.verify";
pub const QUEUE_RESET_PASSWORD: &str = "email.reset_password";
pub const QUEUE_ORG_INVITE: &str = "email.org_invite";

const RETRY_LIMIT: i32 = 3;
const RETRY_DELAY_SECONDS: i32 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailPayload {
    pub to: String,
    pub name: String,
    pub verify_url: String,
    #[serde(default)]
    pub locale: Locale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordPayload {
    pub to: String,
    pub reset_url: String,
    #[serde(default)]
    pub locale: Locale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgInvitePayload {
    pub to: String,
    pub organization_name: String,
    pub inviter_name: String,
    pub role: String,
    pub accept_url: String,
    #[serde(default)]
    pub locale: Locale,
}

pub async fn enqueue<T: Serialize>(
    boss: &Client,
    queue_name: &str,
    payload: &T,
) -> anyhow::Result<Uuid> {
    let data = serde_json::to_value(payload).context("Falha ao serializar payload do job")?;
    let job = Job::builder()
        .queue_name(queue_name)
        .data(data)
        .retry_limit(RETRY_LIMIT as usize)
        .retry_delay(Duration::from_secs(RETRY_DELAY_SECONDS as u64))
        .build();

    boss.send_job(&job)
        .await
        .context("Falha ao enfileirar job no pgboss")
}

pub async fn enqueue_transactional<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    queue_name: &str,
    payload: &T,
) -> anyhow::Result<Uuid> {
    // Mirrors pgboss 0.1.0-rc5's create_job for the default schema used by Client::with_pool.
    // Queue defaults must be copied at enqueue time, as they are by pgboss.
    sqlx::query_scalar(
        r#"
        INSERT INTO pgboss.job (
            id, name, data, priority, start_after, singleton_key, singleton_on,
            expire_seconds, deletion_seconds, keep_until, retry_limit, retry_delay,
            retry_backoff, retry_delay_max, policy, dead_letter
        )
        SELECT
            gen_random_uuid(), $1, $2::jsonb, 0, now(), NULL, NULL,
            q.expire_seconds, q.deletion_seconds,
            now() + q.retention_seconds * interval '1s', $3, $4,
            COALESCE(q.retry_backoff, false), q.retry_delay_max, q.policy, q.dead_letter
        FROM pgboss.queue q
        WHERE q.name = $1
        RETURNING id
        "#,
    )
    .bind(queue_name)
    .bind(Json(payload))
    .bind(RETRY_LIMIT)
    .bind(RETRY_DELAY_SECONDS)
    .fetch_one(&mut **tx)
    .await
    .context("Falha ao enfileirar job no pgboss")
}

pub fn spawn_workers(boss: Client, mailer: ResendMailer) {
    for queue in [QUEUE_VERIFY_EMAIL, QUEUE_RESET_PASSWORD, QUEUE_ORG_INVITE] {
        let boss = boss.clone();
        let mailer = mailer.clone();
        tokio::spawn(async move {
            loop {
                match boss.fetch_job(queue).await {
                    Ok(Some(job)) => {
                        let result = process_job(queue, job.data, &mailer).await;
                        let update = match result {
                            Ok(()) => {
                                boss.complete_job(queue, job.id, serde_json::Value::Null)
                                    .await
                            }
                            Err(err) => {
                                tracing::error!(queue, job_id = %job.id, error = %format!("{err:#}"), "Falha ao processar job pgboss");
                                boss.fail_job(queue, job.id).await
                            }
                        };
                        match update {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!(queue, job_id = %job.id, "Estado do job pgboss não atualizado")
                            }
                            Err(err) => {
                                tracing::error!(queue, job_id = %job.id, error = %err, "Falha ao atualizar estado do job pgboss")
                            }
                        }
                    }
                    Ok(None) => tokio::time::sleep(Duration::from_secs(1)).await,
                    Err(err) => {
                        tracing::error!(queue, error = %err, "Falha ao buscar job pgboss");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(err) = boss.force_maintain().await {
                tracing::error!(error = %err, "Falha na manutenção do pgboss");
            }
        }
    });
}

async fn process_job(
    queue: &str,
    data: serde_json::Value,
    mailer: &ResendMailer,
) -> anyhow::Result<()> {
    match queue {
        QUEUE_VERIFY_EMAIL => {
            let payload: VerifyEmailPayload =
                serde_json::from_value(data).context("Payload inválido em email.verify")?;
            let (subject, html) = verification_email(&payload)?;
            mailer.send_html(&payload.to, subject, &html).await
        }
        QUEUE_RESET_PASSWORD => {
            let payload: ResetPasswordPayload =
                serde_json::from_value(data).context("Payload inválido em email.reset_password")?;
            let (subject, html) = reset_password_email(&payload)?;
            mailer.send_html(&payload.to, subject, &html).await
        }
        QUEUE_ORG_INVITE => {
            let payload: OrgInvitePayload =
                serde_json::from_value(data).context("Payload inválido em email.org_invite")?;
            let (subject, html) = org_invite_email(&payload)?;
            mailer.send_html(&payload.to, subject, &html).await
        }
        _ => anyhow::bail!("Fila desconhecida: {queue}"),
    }
}

fn verification_email(payload: &VerifyEmailPayload) -> anyhow::Result<(&'static str, String)> {
    let name = escape(&payload.name, Html)?;
    let url = escape(&payload.verify_url, Html)?;
    Ok(match payload.locale {
        Locale::Pt => (
            "Confirme seu e-mail",
            format!(
                r#"<h2>Olá, {name}!</h2>
                <p>Confirme seu cadastro clicando no link abaixo (válido por 24 horas):</p>
                <p><a href="{url}">Confirmar meu e-mail</a></p>"#
            ),
        ),
        Locale::Es => (
            "Confirma tu correo electrónico",
            format!(
                r#"<h2>¡Hola, {name}!</h2>
                <p>Confirma tu registro haciendo clic en el siguiente enlace (válido durante 24 horas):</p>
                <p><a href="{url}">Confirmar mi correo electrónico</a></p>"#
            ),
        ),
    })
}

fn reset_password_email(payload: &ResetPasswordPayload) -> anyhow::Result<(&'static str, String)> {
    let url = escape(&payload.reset_url, Html)?;
    Ok(match payload.locale {
        Locale::Pt => (
            "Redefinição de senha",
            format!(
                r#"<h2>Redefinição de senha</h2>
                <p>Recebemos um pedido para redefinir sua senha. O link abaixo expira em 1 hora:</p>
                <p><a href="{url}">Redefinir minha senha</a></p>
                <p>Se você não solicitou isso, ignore este e-mail.</p>"#
            ),
        ),
        Locale::Es => (
            "Restablecimiento de contraseña",
            format!(
                r#"<h2>Restablecimiento de contraseña</h2>
                <p>Hemos recibido una solicitud para restablecer tu contraseña. El siguiente enlace caduca en 1 hora:</p>
                <p><a href="{url}">Restablecer mi contraseña</a></p>
                <p>Si no lo solicitaste, ignora este correo electrónico.</p>"#
            ),
        ),
    })
}

fn org_invite_email(payload: &OrgInvitePayload) -> anyhow::Result<(&'static str, String)> {
    let org = escape(&payload.organization_name, Html)?;
    let inviter = escape(&payload.inviter_name, Html)?;
    let role = escape(&payload.role, Html)?;
    let url = escape(&payload.accept_url, Html)?;
    Ok(match payload.locale {
        Locale::Pt => (
            "Convite para organização",
            format!(
                r#"<h2>Você foi convidado para {org}</h2>
                <p>{inviter} convidou você para entrar em <strong>{org}</strong> como <strong>{role}</strong> (válido por 7 dias):</p>
                <p><a href="{url}">Aceitar convite</a></p>"#
            ),
        ),
        Locale::Es => (
            "Invitación a una organización",
            format!(
                r#"<h2>Has recibido una invitación a {org}</h2>
                <p>{inviter} te invitó a unirte a <strong>{org}</strong> como <strong>{role}</strong> (válido durante 7 días):</p>
                <p><a href="{url}">Aceptar invitación</a></p>"#
            ),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sqlx::PgPool;

    #[test]
    fn old_email_jobs_default_to_portuguese() -> anyhow::Result<()> {
        let verification: VerifyEmailPayload = serde_json::from_value(json!({
            "to": "ana@example.com",
            "name": "Ana",
            "verify_url": "https://example.com/verify-email?token=123"
        }))?;
        let reset: ResetPasswordPayload = serde_json::from_value(json!({
            "to": "ana@example.com",
            "reset_url": "https://example.com/reset-password?token=123"
        }))?;

        assert_eq!(verification.locale, Locale::Pt);
        assert_eq!(reset.locale, Locale::Pt);
        let (subject, html) = verification_email(&verification)?;
        assert_eq!(subject, "Confirme seu e-mail");
        assert!(html.contains("Olá, Ana!"));
        let (subject, html) = reset_password_email(&reset)?;
        assert_eq!(subject, "Redefinição de senha");
        assert!(html.contains("Redefinir minha senha"));
        Ok(())
    }

    #[test]
    fn spanish_email_jobs_are_localized_and_html_escaped() -> anyhow::Result<()> {
        let verification = VerifyEmailPayload {
            to: "ana@example.com".into(),
            name: "Ana <script>&\"'".into(),
            verify_url: "https://example.com/verify-email?token=123&locale=es\" onclick=\"bad"
                .into(),
            locale: Locale::Es,
        };
        let reset = ResetPasswordPayload {
            to: "ana@example.com".into(),
            reset_url: "https://example.com/reset-password?token=123&locale=es\" onclick=\"bad"
                .into(),
            locale: Locale::Es,
        };
        assert_eq!(serde_json::to_value(&verification)?["locale"], "es");
        assert_eq!(serde_json::to_value(&reset)?["locale"], "es");

        let (subject, html) = verification_email(&verification)?;
        assert_eq!(subject, "Confirma tu correo electrónico");
        assert!(html.contains("¡Hola, Ana &#60;script&#62;&#38;&#34;&#39;!"));
        assert!(html.contains("token=123&#38;locale=es&#34; onclick=&#34;bad"));
        assert!(html.contains("Confirmar mi correo electrónico"));
        let (subject, html) = reset_password_email(&reset)?;
        assert_eq!(subject, "Restablecimiento de contraseña");
        assert!(html.contains("token=123&#38;locale=es&#34; onclick=&#34;bad"));
        assert!(html.contains("Restablecer mi contraseña"));
        assert!(html.contains("Si no lo solicitaste"));
        Ok(())
    }

    #[test]
    fn org_invite_emails_are_localized_and_html_escaped() -> anyhow::Result<()> {
        let payload = OrgInvitePayload {
            to: "dev@example.com".into(),
            organization_name: "Acme <Corp>".into(),
            inviter_name: "Ana & Bob".into(),
            role: "admin".into(),
            accept_url: "https://example.com/invites/accept?token=abc&locale=es".into(),
            locale: Locale::Es,
        };
        let (subject, html) = org_invite_email(&payload)?;
        assert_eq!(subject, "Invitación a una organización");
        assert!(html.contains("Acme &#60;Corp&#62;"));
        assert!(html.contains("Ana &#38; Bob"));
        assert!(html.contains("token=abc&#38;locale=es"));
        assert!(html.contains("Aceptar invitación"));
        Ok(())
    }

    async fn insert_registration(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO users (id, email, name, password_hash) VALUES ($1, $2, 'Ana', 'hash')",
        )
        .bind(user_id)
        .bind(format!("{user_id}@example.com"))
        .execute(&mut **tx)
        .await?;
        sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, now() + interval '1 day')")
            .bind(format!("session-{user_id}"))
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("INSERT INTO auth_tokens (token, user_id, purpose, expires_at) VALUES ($1, $2, 'verify_email', now() + interval '1 day')")
            .bind(format!("token-{user_id}"))
            .bind(user_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn registration_visibility(
        pool: &PgPool,
        user_id: Uuid,
        job_id: Uuid,
    ) -> anyhow::Result<(bool, bool, bool, bool)> {
        Ok(sqlx::query_as(
            r#"
            SELECT EXISTS(SELECT 1 FROM users WHERE id = $1),
                   EXISTS(SELECT 1 FROM sessions WHERE user_id = $1),
                   EXISTS(SELECT 1 FROM auth_tokens WHERE user_id = $1),
                   EXISTS(SELECT 1 FROM pgboss.job WHERE id = $2)
            "#,
        )
        .bind(user_id)
        .bind(job_id)
        .fetch_one(pool)
        .await?)
    }

    #[sqlx::test]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn transactional_enqueue_matches_pgboss_and_registration_rolls_back(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let boss = Client::with_pool(pool.clone()).await?;
        boss.create_standard_queue(QUEUE_VERIFY_EMAIL).await?;
        boss.create_standard_queue("email.dead_letter").await?;
        sqlx::query(
            r#"
            UPDATE pgboss.queue
            SET retry_limit = 9, retry_delay = 99, retry_backoff = true,
                retry_delay_max = 222, expire_seconds = 240, retention_seconds = 3600,
                deletion_seconds = 7200, dead_letter = 'email.dead_letter'
            WHERE name = $1
            "#,
        )
        .bind(QUEUE_VERIFY_EMAIL)
        .execute(&pool)
        .await?;

        let payload = VerifyEmailPayload {
            to: "ana@example.com".into(),
            name: "Ana".into(),
            verify_url: "https://example.com/verify-email?token=123&locale=es".into(),
            locale: Locale::Es,
        };
        let regular_id = enqueue(&boss, QUEUE_VERIFY_EMAIL, &payload).await?;
        let user_id = Uuid::new_v4();
        let mut tx = pool.begin().await?;
        insert_registration(&mut tx, user_id).await?;
        let job_id = enqueue_transactional(&mut tx, QUEUE_VERIFY_EMAIL, &payload).await?;
        assert_eq!(
            registration_visibility(&pool, user_id, job_id).await?,
            (false, false, false, false)
        );
        tx.commit().await?;
        assert_eq!(
            registration_visibility(&pool, user_id, job_id).await?,
            (true, true, true, true)
        );

        let same_options: bool = sqlx::query_scalar(
            r#"
            SELECT a.data = b.data AND a.priority = b.priority
               AND a.retry_limit = b.retry_limit AND a.retry_delay = b.retry_delay
               AND a.retry_backoff = b.retry_backoff
               AND a.retry_delay_max IS NOT DISTINCT FROM b.retry_delay_max
               AND a.expire_seconds = b.expire_seconds
               AND a.deletion_seconds = b.deletion_seconds
               AND a.keep_until - a.start_after = b.keep_until - b.start_after
               AND a.policy IS NOT DISTINCT FROM b.policy
               AND a.dead_letter IS NOT DISTINCT FROM b.dead_letter
               AND a.singleton_key IS NOT DISTINCT FROM b.singleton_key
               AND a.singleton_on IS NOT DISTINCT FROM b.singleton_on
            FROM pgboss.job a CROSS JOIN pgboss.job b
            WHERE a.id = $1 AND b.id = $2
            "#,
        )
        .bind(regular_id)
        .bind(job_id)
        .fetch_one(&pool)
        .await?;
        assert!(same_options);
        let options: (i32, i32, bool, Option<i32>, i32, i32, i64) = sqlx::query_as(
            r#"
            SELECT retry_limit, retry_delay, retry_backoff, retry_delay_max,
                   expire_seconds, deletion_seconds,
                   extract(epoch FROM keep_until - start_after)::bigint
            FROM pgboss.job WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(options, (3, 30, true, Some(222), 240, 7200, 3600));

        let failed_user = Uuid::new_v4();
        let failed: anyhow::Result<()> = async {
            let mut tx = pool.begin().await?;
            insert_registration(&mut tx, failed_user).await?;
            enqueue_transactional(&mut tx, "email.missing", &payload).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        assert!(failed.is_err());
        assert_eq!(
            registration_visibility(&pool, failed_user, Uuid::nil()).await?,
            (false, false, false, false)
        );

        boss.create_standard_queue("email.short").await?;
        sqlx::query("UPDATE pgboss.queue SET policy = 'short' WHERE name = 'email.short'")
            .execute(&pool)
            .await?;
        enqueue(&boss, "email.short", &payload).await?;
        let conflict_user = Uuid::new_v4();
        let conflict: anyhow::Result<()> = async {
            let mut tx = pool.begin().await?;
            insert_registration(&mut tx, conflict_user).await?;
            enqueue_transactional(&mut tx, "email.short", &payload).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        assert!(conflict.is_err());
        assert_eq!(
            registration_visibility(&pool, conflict_user, Uuid::nil()).await?,
            (false, false, false, false)
        );

        let rolled_back_user = Uuid::new_v4();
        let mut tx = pool.begin().await?;
        insert_registration(&mut tx, rolled_back_user).await?;
        let rolled_back_job = enqueue_transactional(&mut tx, QUEUE_VERIFY_EMAIL, &payload).await?;
        tx.rollback().await?;
        assert_eq!(
            registration_visibility(&pool, rolled_back_user, rolled_back_job).await?,
            (false, false, false, false)
        );

        for _ in 0..2 {
            let job = boss
                .fetch_job(QUEUE_VERIFY_EMAIL)
                .await?
                .expect("job should be visible");
            assert!(job.id == regular_id || job.id == job_id);
            assert_eq!(job.data, serde_json::to_value(&payload)?);
        }
        Ok(())
    }
}
