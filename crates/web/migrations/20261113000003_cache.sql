-- Cache em PostgreSQL substituindo Redis: tabela UNLOGGED (sem overhead de WAL)
-- e coluna TEXT armazenando payloads JSON, com expiração gerenciada por stored procedures.

CREATE UNLOGGED TABLE IF NOT EXISTS cache_entries (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at
    ON cache_entries (expires_at)
    WHERE expires_at IS NOT NULL;

CREATE OR REPLACE PROCEDURE cache_set(
    p_key TEXT,
    p_payload TEXT,
    p_ttl_seconds INTEGER DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_ttl_seconds IS NOT NULL AND p_ttl_seconds <= 0 THEN
        DELETE FROM cache_entries WHERE cache_key = p_key;
        RETURN;
    END IF;

    INSERT INTO cache_entries (cache_key, payload, expires_at)
    VALUES (
        p_key,
        p_payload,
        CASE
            WHEN p_ttl_seconds IS NULL THEN NULL
            ELSE clock_timestamp() + make_interval(secs => p_ttl_seconds)
        END
    )
    ON CONFLICT (cache_key) DO UPDATE
    SET payload = EXCLUDED.payload,
        expires_at = EXCLUDED.expires_at;
END;
$$;

CREATE OR REPLACE FUNCTION cache_get(p_key TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_payload TEXT;
    v_expires_at TIMESTAMPTZ;
BEGIN
    SELECT payload, expires_at
    INTO v_payload, v_expires_at
    FROM cache_entries
    WHERE cache_key = p_key;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF v_expires_at IS NOT NULL AND v_expires_at <= clock_timestamp() THEN
        DELETE FROM cache_entries
        WHERE cache_key = p_key
          AND expires_at IS NOT NULL
          AND expires_at <= clock_timestamp();
        RETURN NULL;
    END IF;

    RETURN v_payload;
END;
$$;

CREATE OR REPLACE FUNCTION cache_ttl(p_key TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_expires_at TIMESTAMPTZ;
    v_remaining BIGINT;
BEGIN
    SELECT expires_at
    INTO v_expires_at
    FROM cache_entries
    WHERE cache_key = p_key;

    IF NOT FOUND THEN
        RETURN -2;
    END IF;

    IF v_expires_at IS NULL THEN
        RETURN -1;
    END IF;

    IF v_expires_at <= clock_timestamp() THEN
        DELETE FROM cache_entries
        WHERE cache_key = p_key
          AND expires_at IS NOT NULL
          AND expires_at <= clock_timestamp();
        RETURN -2;
    END IF;

    v_remaining := FLOOR(EXTRACT(EPOCH FROM (v_expires_at - clock_timestamp())))::BIGINT;
    RETURN GREATEST(v_remaining, 0);
END;
$$;

CREATE OR REPLACE PROCEDURE cache_del(p_key TEXT)
LANGUAGE sql
AS $$
    DELETE FROM cache_entries WHERE cache_key = p_key;
$$;

CREATE OR REPLACE PROCEDURE cache_del_prefix(p_prefix TEXT)
LANGUAGE sql
AS $$
    DELETE FROM cache_entries WHERE starts_with(cache_key, p_prefix);
$$;

CREATE OR REPLACE PROCEDURE cache_purge_expired(INOUT p_deleted BIGINT DEFAULT 0)
LANGUAGE plpgsql
AS $$
BEGIN
    WITH deleted AS (
        DELETE FROM cache_entries
        WHERE expires_at IS NOT NULL
          AND expires_at <= clock_timestamp()
        RETURNING 1
    )
    SELECT count(*) INTO p_deleted FROM deleted;
END;
$$;
