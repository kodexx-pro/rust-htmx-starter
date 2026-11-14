use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct CronJob {
    pub jobid: i64,
    pub schedule: String,
    pub command: String,
    pub nodename: String,
    pub nodeport: i32,
    pub database: String,
    pub username: String,
    pub active: bool,
    pub jobname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct CronJobRun {
    pub runid: i64,
    pub jobid: Option<i64>,
    pub job_pid: Option<i32>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub command: Option<String>,
    pub status: Option<String>,
    pub return_message: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Clone)]
pub struct PgCron {
    db: PgPool,
}

impl PgCron {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn is_enabled(&self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')",
        )
        .fetch_one(&self.db)
        .await
        .unwrap_or(false)
    }

    pub async fn schedule(&self, name: &str, schedule: &str, command: &str) -> anyhow::Result<i64> {
        let (name, schedule, command) = validate_job_args(name, schedule, command)?;

        sqlx::query_scalar("SELECT cron.schedule($1, $2, $3)")
            .bind(name)
            .bind(schedule)
            .bind(command)
            .fetch_one(&self.db)
            .await
            .context("Falha ao agendar cronjob no pg_cron")
    }

    pub async fn schedule_in_database(
        &self,
        name: &str,
        schedule: &str,
        command: &str,
        database: &str,
    ) -> anyhow::Result<i64> {
        let (name, schedule, command) = validate_job_args(name, schedule, command)?;
        let database = database.trim();
        ensure!(
            !database.is_empty(),
            "Nome do banco de dados não pode ser vazio"
        );

        sqlx::query_scalar("SELECT cron.schedule_in_database($1, $2, $3, $4)")
            .bind(name)
            .bind(schedule)
            .bind(command)
            .bind(database)
            .fetch_one(&self.db)
            .await
            .context("Falha ao agendar cronjob em outro banco no pg_cron")
    }

    pub async fn unschedule(&self, name: &str) -> anyhow::Result<bool> {
        let name = name.trim();
        ensure!(!name.is_empty(), "Nome do cronjob não pode ser vazio");

        // `cron.unschedule(text)` lança erro se o job não existir; consultamos antes para retornar Ok(false).
        let removed: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT cron.unschedule(jobname)
            FROM cron.job
            WHERE jobname = $1 AND username = CURRENT_USER
            "#,
        )
        .bind(name)
        .fetch_optional(&self.db)
        .await
        .context("Falha ao remover cronjob no pg_cron")?;

        Ok(removed.unwrap_or(false))
    }

    pub async fn set_active(&self, job_id: i64, active: bool) -> anyhow::Result<()> {
        sqlx::query("SELECT cron.alter_job(job_id => $1, active => $2)")
            .bind(job_id)
            .bind(active)
            .execute(&self.db)
            .await
            .context("Falha ao alterar estado do cronjob no pg_cron")?;
        Ok(())
    }

    pub async fn job_by_name(&self, name: &str) -> anyhow::Result<Option<CronJob>> {
        sqlx::query_as::<_, CronJob>(
            r#"
            SELECT jobid, schedule, command, nodename, nodeport, database, username, active, jobname
            FROM cron.job
            WHERE jobname = $1 AND username = CURRENT_USER
            "#,
        )
        .bind(name.trim())
        .fetch_optional(&self.db)
        .await
        .context("Falha ao buscar cronjob no pg_cron")
    }

    pub async fn list_jobs(&self) -> anyhow::Result<Vec<CronJob>> {
        sqlx::query_as::<_, CronJob>(
            r#"
            SELECT jobid, schedule, command, nodename, nodeport, database, username, active, jobname
            FROM cron.job
            ORDER BY jobid ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .context("Falha ao listar cronjobs no pg_cron")
    }

    pub async fn recent_runs(&self, limit: i64) -> anyhow::Result<Vec<CronJobRun>> {
        let clamped_limit = limit.clamp(1, 500);
        sqlx::query_as::<_, CronJobRun>(
            r#"
            SELECT
                runid,
                jobid,
                job_pid,
                database,
                username,
                command,
                status,
                return_message,
                start_time::text AS start_time,
                end_time::text AS end_time
            FROM cron.job_run_details
            ORDER BY runid DESC
            LIMIT $1
            "#,
        )
        .bind(clamped_limit)
        .fetch_all(&self.db)
        .await
        .context("Falha ao listar histórico de execuções do pg_cron")
    }
}

fn validate_job_args<'a>(
    name: &'a str,
    schedule: &'a str,
    command: &'a str,
) -> anyhow::Result<(&'a str, &'a str, &'a str)> {
    let name = name.trim();
    let schedule = schedule.trim();
    let command = command.trim();
    ensure!(!name.is_empty(), "Nome do cronjob não pode ser vazio");
    ensure!(!schedule.is_empty(), "Expressão cron não pode ser vazia");
    ensure!(
        !command.is_empty(),
        "Comando SQL do cronjob não pode ser vazio"
    );
    Ok((name, schedule, command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_cron_job_arguments() {
        assert!(validate_job_args(" ", "* * * * *", "SELECT 1").is_err());
        assert!(validate_job_args("job", "", "SELECT 1").is_err());
        assert!(validate_job_args("job", "* * * * *", "   ").is_err());
        assert_eq!(
            validate_job_args(" job ", " */5 * * * * ", " SELECT 1 ").unwrap(),
            ("job", "*/5 * * * *", "SELECT 1")
        );
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL configured with shared_preload_libraries=pg_cron and DATABASE_URL"]
    async fn pg_cron_schedules_updates_pauses_and_unschedules_jobs() -> anyhow::Result<()> {
        let database_url = std::env::var("DATABASE_URL")?;
        let pool = PgPool::connect(&database_url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;

        let cron = PgCron::new(pool);
        assert!(cron.is_enabled().await);

        let default_jobs = cron.list_jobs().await?;
        for required in [
            "cleanup-expired-cache",
            "cleanup-expired-sessions",
            "cleanup-expired-auth-tokens",
            "cleanup-cron-history",
        ] {
            assert!(
                default_jobs
                    .iter()
                    .any(|j| j.jobname.as_deref() == Some(required) && j.active),
                "Expected default pg_cron job '{required}' to be active"
            );
        }

        let job_name = format!("test-cron-{}", uuid::Uuid::new_v4());
        let job_id = cron.schedule(&job_name, "*/10 * * * *", "SELECT 1").await?;

        // Reagendamento com o mesmo nome atualiza o mesmo jobid em vez de duplicar
        let updated_id = cron.schedule(&job_name, "*/5 * * * *", "SELECT 2").await?;
        assert_eq!(job_id, updated_id);

        cron.set_active(job_id, false).await?;
        let paused = cron.job_by_name(&job_name).await?.unwrap();
        assert!(!paused.active);
        assert_eq!(paused.schedule, "*/5 * * * *");
        assert_eq!(paused.command, "SELECT 2");

        assert!(cron.unschedule(&job_name).await?);
        assert!(!cron.unschedule(&job_name).await?);
        assert!(cron.job_by_name(&job_name).await?.is_none());

        Ok(())
    }
}
