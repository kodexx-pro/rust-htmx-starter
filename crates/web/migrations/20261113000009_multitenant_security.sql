-- Pilar 1 (convites multi-tenant) + Pilar 2 (rate limiting atômico via UNLOGGED cache_entries)

CREATE OR REPLACE FUNCTION cache_incr(
    p_key TEXT,
    p_ttl_seconds INTEGER
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_count BIGINT;
    v_now TIMESTAMPTZ := clock_timestamp();
    v_expires TIMESTAMPTZ := v_now + make_interval(secs => GREATEST(p_ttl_seconds, 1));
BEGIN
    INSERT INTO cache_entries (cache_key, payload, expires_at)
    VALUES (p_key, '1', v_expires)
    ON CONFLICT (cache_key) DO UPDATE
    SET payload = CASE
            WHEN cache_entries.expires_at IS NOT NULL AND cache_entries.expires_at <= v_now THEN '1'
            ELSE ((cache_entries.payload::bigint) + 1)::text
        END,
        expires_at = CASE
            WHEN cache_entries.expires_at IS NOT NULL AND cache_entries.expires_at <= v_now THEN v_expires
            ELSE cache_entries.expires_at
        END
    RETURNING payload::bigint INTO v_count;

    RETURN v_count;
END;
$$;

CREATE TABLE IF NOT EXISTS organization_invites (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (email = LOWER(email)),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    token_hash TEXT NOT NULL UNIQUE,
    invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_organization_invites_pending_email
    ON organization_invites (organization_id, email)
    WHERE accepted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_organization_invites_org_created
    ON organization_invites (organization_id, created_at DESC);

DO $$
BEGIN
    IF current_database() = current_setting('cron.database_name', true) THEN
        PERFORM cron.schedule(
            'cleanup-expired-org-invites',
            '0 3 * * *',
            'DELETE FROM organization_invites WHERE (accepted_at IS NULL AND expires_at <= NOW() - INTERVAL ''1 day'') OR (accepted_at IS NOT NULL AND accepted_at <= NOW() - INTERVAL ''30 days'')'
        );
    END IF;
END
$$;
