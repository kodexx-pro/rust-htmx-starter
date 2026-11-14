CREATE TABLE analytics_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type TEXT NOT NULL CHECK (event_type IN ('page_view', 'click', 'page_leave', 'custom')),
    event_name TEXT NOT NULL,
    visitor_id UUID NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    request_id TEXT,
    path TEXT NOT NULL,
    referrer TEXT,
    page_title TEXT,
    element_tag TEXT,
    element_label TEXT,
    element_target TEXT,
    click_x_pct SMALLINT,
    click_y_pct SMALLINT,
    duration_ms INTEGER,
    locale TEXT,
    timezone TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    device_type TEXT,
    viewport TEXT,
    ip_hash TEXT,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_analytics_events_occurred_at
    ON analytics_events (occurred_at DESC);

CREATE INDEX idx_analytics_events_type_occurred_at
    ON analytics_events (event_type, occurred_at DESC);

CREATE INDEX idx_analytics_events_user_id
    ON analytics_events (user_id, occurred_at DESC)
    WHERE user_id IS NOT NULL;

CREATE INDEX idx_analytics_events_org_id
    ON analytics_events (organization_id, occurred_at DESC)
    WHERE organization_id IS NOT NULL;

CREATE INDEX idx_analytics_events_path
    ON analytics_events (path, occurred_at DESC);

-- Retenção automática de eventos de uso via pg_cron (90 dias) no banco principal
DO $$
BEGIN
    IF current_database() = current_setting('cron.database_name', true) THEN
        PERFORM cron.schedule(
            'cleanup-old-analytics',
            '0 5 * * *',
            'DELETE FROM analytics_events WHERE occurred_at < NOW() - INTERVAL ''90 days'''
        );
    END IF;
END
$$;
