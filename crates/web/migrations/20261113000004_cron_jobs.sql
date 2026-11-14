-- Instala pg_cron quando executando no banco configurado em cron.database_name
-- (evita falhas em bancos efêmeros de teste como _sqlx_test_* onde pg_cron não pode ser criado).
DO $$
BEGIN
    IF current_database() = current_setting('cron.database_name', true) THEN
        CREATE EXTENSION IF NOT EXISTS pg_cron;

        PERFORM cron.schedule(
            'cleanup-expired-cache',
            '* * * * *',
            'CALL cache_purge_expired()'
        );

        PERFORM cron.schedule(
            'cleanup-expired-sessions',
            '*/15 * * * *',
            'DELETE FROM sessions WHERE expires_at <= NOW()'
        );

        PERFORM cron.schedule(
            'cleanup-expired-auth-tokens',
            '0 3 * * *',
            'DELETE FROM auth_tokens WHERE expires_at <= NOW() - INTERVAL ''1 day'' OR (used_at IS NOT NULL AND used_at <= NOW() - INTERVAL ''7 days'')'
        );

        PERFORM cron.schedule(
            'cleanup-cron-history',
            '0 4 * * *',
            'DELETE FROM cron.job_run_details WHERE end_time < NOW() - INTERVAL ''7 days'''
        );
    END IF;
END
$$;
