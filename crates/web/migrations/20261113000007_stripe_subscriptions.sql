CREATE TABLE IF NOT EXISTS organization_subscriptions (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_customer_id TEXT UNIQUE,
    stripe_subscription_id TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'inactive' CHECK (
        status IN (
            'inactive',
            'trialing',
            'active',
            'past_due',
            'canceled',
            'unpaid',
            'paused',
            'incomplete',
            'incomplete_expired'
        )
    ),
    plan_name TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    canceled_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_subscriptions_status
    ON organization_subscriptions (status);

CREATE INDEX IF NOT EXISTS idx_org_subscriptions_customer_id
    ON organization_subscriptions (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_org_subscriptions_subscription_id
    ON organization_subscriptions (stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    stripe_event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    payload JSONB NOT NULL,
    processing_status TEXT NOT NULL DEFAULT 'processed' CHECK (
        processing_status IN ('processed', 'ignored', 'failed')
    ),
    error_message TEXT,
    stripe_created_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_received_at
    ON stripe_webhook_events (received_at DESC);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_org_id
    ON stripe_webhook_events (organization_id, received_at DESC)
    WHERE organization_id IS NOT NULL;
