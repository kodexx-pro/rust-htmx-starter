use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use domain::SubscriptionStatus;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use sqlx::{Executor, FromRow, PgPool, Postgres};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{AppState, cache::PgCache};

type HmacSha256 = Hmac<Sha256>;

const ORG_SUBSCRIPTION_CACHE_TTL: Duration = Duration::from_secs(300);
const STRIPE_SIGNATURE_TOLERANCE_SECS: i64 = 300;

fn org_subscription_cache_key(org_id: Uuid) -> String {
    format!("org_sub:{org_id}")
}

pub async fn invalidate_org_subscription_cache(cache: &PgCache, org_id: Uuid) {
    let _ = cache.delete(&org_subscription_cache_key(org_id)).await;
}

#[derive(Clone)]
pub struct StripeWebhookConfig {
    signing_secret: String,
}

impl StripeWebhookConfig {
    pub fn from_env() -> Option<Self> {
        let secret = std::env::var("STRIPE_WEBHOOK_SECRET")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        Some(Self {
            signing_secret: secret,
        })
    }

    pub fn from_secret(signing_secret: impl Into<String>) -> Self {
        Self {
            signing_secret: signing_secret.into(),
        }
    }

    pub fn verify_signature(
        &self,
        signature_header: &str,
        payload: &[u8],
        now_unix: i64,
    ) -> Result<(), &'static str> {
        let mut timestamp: Option<i64> = None;
        let mut signatures_v1: Vec<&str> = Vec::new();

        for part in signature_header.split(',') {
            let part = part.trim();
            if let Some(raw_ts) = part.strip_prefix("t=") {
                timestamp = raw_ts.parse::<i64>().ok();
            } else if let Some(sig) = part.strip_prefix("v1=")
                && !sig.is_empty()
            {
                signatures_v1.push(sig);
            }
        }

        let Some(ts) = timestamp else {
            return Err("Cabeçalho Stripe-Signature sem timestamp válido");
        };
        if signatures_v1.is_empty() {
            return Err("Cabeçalho Stripe-Signature sem assinatura v1");
        }
        if (now_unix - ts).abs() > STRIPE_SIGNATURE_TOLERANCE_SECS {
            return Err("Timestamp do webhook Stripe fora da janela de tolerância");
        }

        let mut mac = HmacSha256::new_from_slice(self.signing_secret.as_bytes())
            .map_err(|_| "Segredo do webhook Stripe inválido")?;
        mac.update(ts.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let expected = mac.finalize().into_bytes();

        for sig_hex in signatures_v1 {
            if let Ok(decoded) = hex::decode(sig_hex)
                && decoded.len() == expected.len()
                && bool::from(decoded.ct_eq(&expected))
            {
                return Ok(());
            }
        }

        Err("Assinatura Stripe-Signature inválida")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrganizationSubscription {
    pub organization_id: Uuid,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub status: String,
    pub plan_name: Option<String>,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
}

impl OrganizationSubscription {
    pub fn inactive(organization_id: Uuid) -> Self {
        Self {
            organization_id,
            stripe_customer_id: None,
            stripe_subscription_id: None,
            status: SubscriptionStatus::Inactive.as_str().to_string(),
            plan_name: None,
            current_period_end: None,
            cancel_at_period_end: false,
        }
    }

    pub fn parsed_status(&self) -> SubscriptionStatus {
        SubscriptionStatus::parse(&self.status).unwrap_or_default()
    }

    pub fn is_active(&self) -> bool {
        self.parsed_status().is_active()
    }
}

#[derive(FromRow)]
struct SubscriptionRow {
    organization_id: Uuid,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    status: String,
    plan_name: Option<String>,
    current_period_end: Option<String>,
    cancel_at_period_end: bool,
}

pub async fn get_organization_subscription(
    db: &PgPool,
    cache: &PgCache,
    organization_id: Uuid,
) -> anyhow::Result<OrganizationSubscription> {
    let key = org_subscription_cache_key(organization_id);
    cache
        .get_or_set(&key, Some(ORG_SUBSCRIPTION_CACHE_TTL), || async {
            let row = sqlx::query_as::<_, SubscriptionRow>(
                r#"
                SELECT
                    organization_id,
                    stripe_customer_id,
                    stripe_subscription_id,
                    status,
                    plan_name,
                    TO_CHAR(current_period_end AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS current_period_end,
                    cancel_at_period_end
                FROM organization_subscriptions
                WHERE organization_id = $1
                "#,
            )
            .bind(organization_id)
            .fetch_optional(db)
            .await
            .context("Falha ao consultar assinatura da organização")?;

            Ok(match row {
                Some(r) => OrganizationSubscription {
                    organization_id: r.organization_id,
                    stripe_customer_id: r.stripe_customer_id,
                    stripe_subscription_id: r.stripe_subscription_id,
                    status: r.status,
                    plan_name: r.plan_name,
                    current_period_end: r.current_period_end,
                    cancel_at_period_end: r.cancel_at_period_end,
                },
                None => OrganizationSubscription::inactive(organization_id),
            })
        })
        .await
}

#[derive(Deserialize)]
struct StripeEventEnvelope {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    created: Option<i64>,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
    object: Value,
}

pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(config) = state.stripe_webhook.as_ref() else {
        tracing::warn!("Webhook Stripe recebido, mas STRIPE_WEBHOOK_SECRET não está configurado");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "stripe_webhook_not_configured" })),
        )
            .into_response();
    };

    let Some(sig_header) = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing_stripe_signature" })),
        )
            .into_response();
    };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if let Err(reason) = config.verify_signature(sig_header, &body, now_unix) {
        tracing::warn!(reason, "Assinatura de webhook Stripe rejeitada");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_stripe_signature" })),
        )
            .into_response();
    }

    match process_stripe_webhook_payload(&state.db, &state.cache, &body).await {
        Ok(outcome) => (StatusCode::OK, Json(outcome)).into_response(),
        Err(err) => {
            tracing::error!(error = ?err, "Falha ao processar webhook Stripe");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_webhook_payload" })),
            )
                .into_response()
        }
    }
}

pub(crate) async fn process_stripe_webhook_payload(
    db: &PgPool,
    cache: &PgCache,
    raw_body: &[u8],
) -> anyhow::Result<Value> {
    let raw_json: Value =
        serde_json::from_slice(raw_body).context("Payload JSON do webhook Stripe inválido")?;
    let event: StripeEventEnvelope =
        serde_json::from_value(raw_json.clone()).context("Envelope de evento Stripe inválido")?;

    let mut tx = db
        .begin()
        .await
        .context("Falha ao abrir transação de webhook")?;

    let inserted_id: Option<String> = sqlx::query_scalar(
        r#"
        INSERT INTO stripe_webhook_events (
            stripe_event_id,
            event_type,
            payload,
            processing_status,
            stripe_created_at
        )
        VALUES (
            $1,
            $2,
            $3,
            'processed',
            CASE WHEN $4::BIGINT IS NOT NULL THEN to_timestamp($4::DOUBLE PRECISION) ELSE NULL END
        )
        ON CONFLICT (stripe_event_id) DO NOTHING
        RETURNING stripe_event_id
        "#,
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .bind(sqlx::types::Json(&raw_json))
    .bind(event.created)
    .fetch_optional(&mut *tx)
    .await
    .context("Falha ao registrar evento de idempotência Stripe")?;

    if inserted_id.is_none() {
        tx.commit().await?;
        tracing::debug!(
            stripe_event_id = %event.id,
            event_type = %event.event_type,
            "Webhook Stripe duplicado ignorado com segurança"
        );
        return Ok(serde_json::json!({
            "received": true,
            "duplicate": true,
            "event_id": event.id,
        }));
    }

    let obj = &event.data.object;
    let outcome = apply_stripe_event(&mut tx, &event.event_type, obj).await?;

    sqlx::query(
        r#"
        UPDATE stripe_webhook_events
        SET
            organization_id = $2,
            stripe_customer_id = $3,
            stripe_subscription_id = $4,
            processing_status = $5,
            error_message = $6,
            processed_at = NOW()
        WHERE stripe_event_id = $1
        "#,
    )
    .bind(&event.id)
    .bind(outcome.organization_id)
    .bind(&outcome.stripe_customer_id)
    .bind(&outcome.stripe_subscription_id)
    .bind(outcome.processing_status)
    .bind(&outcome.reason)
    .execute(&mut *tx)
    .await
    .context("Falha ao atualizar status do evento Stripe")?;

    tx.commit()
        .await
        .context("Falha ao confirmar transação de webhook Stripe")?;

    if let Some(org_id) = outcome.organization_id
        && outcome.processing_status == "processed"
    {
        invalidate_org_subscription_cache(cache, org_id).await;
    }

    tracing::info!(
        stripe_event_id = %event.id,
        event_type = %event.event_type,
        processing_status = outcome.processing_status,
        organization_id = ?outcome.organization_id,
        "Webhook Stripe processado"
    );

    Ok(serde_json::json!({
        "received": true,
        "duplicate": false,
        "event_id": event.id,
        "status": outcome.processing_status,
    }))
}

struct EventOutcome {
    organization_id: Option<Uuid>,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    processing_status: &'static str,
    reason: Option<String>,
}

async fn apply_stripe_event(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    event_type: &str,
    obj: &Value,
) -> anyhow::Result<EventOutcome> {
    let customer_id = extract_id_or_nested_id(obj.get("customer"));
    let subscription_id = match event_type {
        t if t.starts_with("customer.subscription.") => extract_str(obj, "id"),
        "checkout.session.completed" => extract_id_or_nested_id(obj.get("subscription")),
        t if t.starts_with("invoice.") => {
            extract_id_or_nested_id(obj.get("subscription")).or_else(|| {
                obj.pointer("/parent/subscription_details/subscription")
                    .and_then(|v| extract_id_or_nested_id(Some(v)))
            })
        }
        _ => None,
    };

    let resolved_org = resolve_organization_id(
        &mut **tx,
        obj,
        customer_id.as_deref(),
        subscription_id.as_deref(),
    )
    .await?;

    match event_type {
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted"
        | "customer.subscription.paused"
        | "customer.subscription.resumed"
        | "customer.subscription.trial_will_end" => {
            let Some(org_id) = resolved_org else {
                return Ok(EventOutcome {
                    organization_id: None,
                    stripe_customer_id: customer_id,
                    stripe_subscription_id: subscription_id,
                    processing_status: "ignored",
                    reason: Some(
                        "Organização não encontrada para o evento de assinatura".to_string(),
                    ),
                });
            };

            let raw_status = extract_str(obj, "status").unwrap_or_else(|| {
                if event_type == "customer.subscription.deleted" {
                    "canceled".to_string()
                } else {
                    "inactive".to_string()
                }
            });
            let status = SubscriptionStatus::parse(&raw_status)
                .unwrap_or(SubscriptionStatus::Inactive)
                .as_str()
                .to_string();

            let period_start = extract_i64(obj, "current_period_start").or_else(|| {
                obj.pointer("/items/data/0/current_period_start")
                    .and_then(Value::as_i64)
            });
            let period_end = extract_i64(obj, "current_period_end").or_else(|| {
                obj.pointer("/items/data/0/current_period_end")
                    .and_then(Value::as_i64)
            });
            let cancel_at_period_end = obj
                .get("cancel_at_period_end")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let canceled_at = extract_i64(obj, "canceled_at");
            let plan_name = extract_plan_name(obj);
            let metadata = obj
                .get("metadata")
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));

            sqlx::query(
                r#"
                INSERT INTO organization_subscriptions (
                    organization_id,
                    stripe_customer_id,
                    stripe_subscription_id,
                    status,
                    plan_name,
                    current_period_start,
                    current_period_end,
                    cancel_at_period_end,
                    canceled_at,
                    metadata,
                    updated_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    CASE WHEN $6::BIGINT IS NOT NULL THEN to_timestamp($6::DOUBLE PRECISION) ELSE NULL END,
                    CASE WHEN $7::BIGINT IS NOT NULL THEN to_timestamp($7::DOUBLE PRECISION) ELSE NULL END,
                    $8,
                    CASE WHEN $9::BIGINT IS NOT NULL THEN to_timestamp($9::DOUBLE PRECISION) ELSE NULL END,
                    $10,
                    NOW()
                )
                ON CONFLICT (organization_id) DO UPDATE SET
                    stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, organization_subscriptions.stripe_customer_id),
                    stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, organization_subscriptions.stripe_subscription_id),
                    status = EXCLUDED.status,
                    plan_name = COALESCE(EXCLUDED.plan_name, organization_subscriptions.plan_name),
                    current_period_start = COALESCE(EXCLUDED.current_period_start, organization_subscriptions.current_period_start),
                    current_period_end = COALESCE(EXCLUDED.current_period_end, organization_subscriptions.current_period_end),
                    cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                    canceled_at = COALESCE(EXCLUDED.canceled_at, organization_subscriptions.canceled_at),
                    metadata = EXCLUDED.metadata,
                    updated_at = NOW()
                "#,
            )
            .bind(org_id)
            .bind(&customer_id)
            .bind(&subscription_id)
            .bind(&status)
            .bind(&plan_name)
            .bind(period_start)
            .bind(period_end)
            .bind(cancel_at_period_end)
            .bind(canceled_at)
            .bind(sqlx::types::Json(metadata))
            .execute(&mut **tx)
            .await
            .context("Falha ao atualizar assinatura da organização via webhook")?;

            Ok(EventOutcome {
                organization_id: Some(org_id),
                stripe_customer_id: customer_id,
                stripe_subscription_id: subscription_id,
                processing_status: "processed",
                reason: None,
            })
        }
        "checkout.session.completed" => {
            let Some(org_id) = resolved_org else {
                return Ok(EventOutcome {
                    organization_id: None,
                    stripe_customer_id: customer_id,
                    stripe_subscription_id: subscription_id,
                    processing_status: "ignored",
                    reason: Some(
                        "Organização não identificada em checkout.session.completed".to_string(),
                    ),
                });
            };

            let payment_status = extract_str(obj, "payment_status").unwrap_or_default();
            let fallback_status = if payment_status == "paid" {
                SubscriptionStatus::Active.as_str()
            } else {
                SubscriptionStatus::Incomplete.as_str()
            };
            let plan_name = extract_plan_name(obj);
            let metadata = obj
                .get("metadata")
                .cloned()
                .unwrap_or_else(|| Value::Object(Default::default()));

            sqlx::query(
                r#"
                INSERT INTO organization_subscriptions (
                    organization_id,
                    stripe_customer_id,
                    stripe_subscription_id,
                    status,
                    plan_name,
                    metadata,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, NOW())
                ON CONFLICT (organization_id) DO UPDATE SET
                    stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, organization_subscriptions.stripe_customer_id),
                    stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, organization_subscriptions.stripe_subscription_id),
                    plan_name = COALESCE(EXCLUDED.plan_name, organization_subscriptions.plan_name),
                    status = CASE
                        WHEN organization_subscriptions.status IN ('active', 'trialing')
                            THEN organization_subscriptions.status
                        ELSE EXCLUDED.status
                    END,
                    metadata = CASE
                        WHEN EXCLUDED.metadata = '{}'::jsonb THEN organization_subscriptions.metadata
                        ELSE EXCLUDED.metadata
                    END,
                    updated_at = NOW()
                "#,
            )
            .bind(org_id)
            .bind(&customer_id)
            .bind(&subscription_id)
            .bind(fallback_status)
            .bind(&plan_name)
            .bind(sqlx::types::Json(metadata))
            .execute(&mut **tx)
            .await
            .context("Falha ao vincular checkout Stripe à organização")?;

            Ok(EventOutcome {
                organization_id: Some(org_id),
                stripe_customer_id: customer_id,
                stripe_subscription_id: subscription_id,
                processing_status: "processed",
                reason: None,
            })
        }
        "invoice.paid" | "invoice.payment_succeeded" => {
            let Some(org_id) = resolved_org else {
                return Ok(EventOutcome {
                    organization_id: None,
                    stripe_customer_id: customer_id,
                    stripe_subscription_id: subscription_id,
                    processing_status: "ignored",
                    reason: Some("Organização não encontrada para fatura paga".to_string()),
                });
            };

            let period_start = obj
                .pointer("/lines/data/0/period/start")
                .and_then(Value::as_i64);
            let period_end = obj
                .pointer("/lines/data/0/period/end")
                .and_then(Value::as_i64);

            sqlx::query(
                r#"
                INSERT INTO organization_subscriptions (
                    organization_id,
                    stripe_customer_id,
                    stripe_subscription_id,
                    status,
                    current_period_start,
                    current_period_end,
                    updated_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    'active',
                    CASE WHEN $4::BIGINT IS NOT NULL THEN to_timestamp($4::DOUBLE PRECISION) ELSE NULL END,
                    CASE WHEN $5::BIGINT IS NOT NULL THEN to_timestamp($5::DOUBLE PRECISION) ELSE NULL END,
                    NOW()
                )
                ON CONFLICT (organization_id) DO UPDATE SET
                    stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, organization_subscriptions.stripe_customer_id),
                    stripe_subscription_id = COALESCE(EXCLUDED.stripe_subscription_id, organization_subscriptions.stripe_subscription_id),
                    status = 'active',
                    current_period_start = COALESCE(EXCLUDED.current_period_start, organization_subscriptions.current_period_start),
                    current_period_end = COALESCE(EXCLUDED.current_period_end, organization_subscriptions.current_period_end),
                    updated_at = NOW()
                "#,
            )
            .bind(org_id)
            .bind(&customer_id)
            .bind(&subscription_id)
            .bind(period_start)
            .bind(period_end)
            .execute(&mut **tx)
            .await
            .context("Falha ao ativar assinatura após invoice.paid")?;

            Ok(EventOutcome {
                organization_id: Some(org_id),
                stripe_customer_id: customer_id,
                stripe_subscription_id: subscription_id,
                processing_status: "processed",
                reason: None,
            })
        }
        "invoice.payment_failed" => {
            let Some(org_id) = resolved_org else {
                return Ok(EventOutcome {
                    organization_id: None,
                    stripe_customer_id: customer_id,
                    stripe_subscription_id: subscription_id,
                    processing_status: "ignored",
                    reason: Some("Organização não encontrada para falha de pagamento".to_string()),
                });
            };

            sqlx::query(
                r#"
                UPDATE organization_subscriptions
                SET
                    status = 'past_due',
                    updated_at = NOW()
                WHERE organization_id = $1
                "#,
            )
            .bind(org_id)
            .execute(&mut **tx)
            .await
            .context("Falha ao marcar assinatura como past_due")?;

            Ok(EventOutcome {
                organization_id: Some(org_id),
                stripe_customer_id: customer_id,
                stripe_subscription_id: subscription_id,
                processing_status: "processed",
                reason: None,
            })
        }
        _ => Ok(EventOutcome {
            organization_id: resolved_org,
            stripe_customer_id: customer_id,
            stripe_subscription_id: subscription_id,
            processing_status: "ignored",
            reason: Some(format!("Evento '{event_type}' não altera assinatura")),
        }),
    }
}

async fn resolve_organization_id<'e, E>(
    executor: &mut E,
    obj: &Value,
    customer_id: Option<&str>,
    subscription_id: Option<&str>,
) -> anyhow::Result<Option<Uuid>>
where
    for<'c> &'c mut E: Executor<'c, Database = Postgres>,
{
    let metadata_uuid = obj
        .pointer("/metadata/organization_id")
        .or_else(|| obj.pointer("/metadata/org_id"))
        .or_else(|| obj.get("client_reference_id"))
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok());

    if let Some(candidate) = metadata_uuid {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)")
                .bind(candidate)
                .fetch_one(&mut *executor)
                .await
                .context("Falha ao validar organization_id do metadado Stripe")?;
        if exists {
            return Ok(Some(candidate));
        }
    }

    if let Some(sub_id) = subscription_id {
        let org_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT organization_id FROM organization_subscriptions WHERE stripe_subscription_id = $1",
        )
        .bind(sub_id)
        .fetch_optional(&mut *executor)
        .await
        .context("Falha ao buscar organização por stripe_subscription_id")?;
        if org_id.is_some() {
            return Ok(org_id);
        }
    }

    if let Some(cus_id) = customer_id {
        let org_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT organization_id FROM organization_subscriptions WHERE stripe_customer_id = $1",
        )
        .bind(cus_id)
        .fetch_optional(&mut *executor)
        .await
        .context("Falha ao buscar organização por stripe_customer_id")?;
        if org_id.is_some() {
            return Ok(org_id);
        }
    }

    Ok(None)
}

fn extract_str(obj: &Value, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn extract_i64(obj: &Value, key: &str) -> Option<i64> {
    obj.get(key).and_then(Value::as_i64)
}

fn extract_id_or_nested_id(val: Option<&Value>) -> Option<String> {
    let val = val?;
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        return (!trimmed.is_empty()).then(|| trimmed.to_string());
    }
    val.get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn extract_plan_name(obj: &Value) -> Option<String> {
    obj.pointer("/metadata/plan_name")
        .or_else(|| obj.pointer("/items/data/0/price/nickname"))
        .or_else(|| obj.pointer("/items/data/0/plan/nickname"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
pub(crate) fn sign_test_payload(secret: &str, timestamp: i64, payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={sig}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orgs::create_organization_for_owner;
    use sqlx::PgPool;

    #[test]
    fn verifies_stripe_signature_and_rejects_tampering_or_replay() {
        let secret = "whsec_test_secret_123";
        let config = StripeWebhookConfig::from_secret(secret);
        let payload = br#"{"id":"evt_1","type":"customer.subscription.created"}"#;
        let now = 1_760_000_000;

        let valid_sig = sign_test_payload(secret, now, payload);
        assert!(
            config
                .verify_signature(&valid_sig, payload, now + 10)
                .is_ok()
        );

        let rotated = format!(
            "t={now},v1=deadbeef,{}",
            valid_sig.split(',').nth(1).unwrap()
        );
        assert!(config.verify_signature(&rotated, payload, now).is_ok());

        assert!(
            config
                .verify_signature(&valid_sig, br#"{"tampered":true}"#, now)
                .is_err()
        );
        assert!(
            config
                .verify_signature(&valid_sig, payload, now + 301)
                .is_err()
        );
        assert!(
            StripeWebhookConfig::from_secret("whsec_wrong")
                .verify_signature(&valid_sig, payload, now)
                .is_err()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn webhook_lifecycle_syncs_org_subscription_is_idempotent_and_updates_cache(
        pool: PgPool,
    ) {
        let cache = PgCache::new(pool.clone());
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, name, password_hash) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind("billing@example.com")
            .bind("Billing Owner")
            .bind("hash")
            .execute(&pool)
            .await
            .unwrap();

        let org = create_organization_for_owner(
            &pool,
            &cache,
            user_id,
            "Acme Enterprise",
            "acme-enterprise",
        )
        .await
        .unwrap();

        // Sem registro prévio, retorna inactive
        let initial = get_organization_subscription(&pool, &cache, org.id)
            .await
            .unwrap();
        assert_eq!(initial.parsed_status(), SubscriptionStatus::Inactive);
        assert!(!initial.is_active());

        // 1. customer.subscription.created com metadata.organization_id e plan_name negociado
        let created_payload = serde_json::json!({
            "id": "evt_sub_created_1",
            "type": "customer.subscription.created",
            "created": 1760000000,
            "data": {
                "object": {
                    "id": "sub_123",
                    "customer": "cus_123",
                    "status": "active",
                    "current_period_start": 1760000000,
                    "current_period_end": 1762678400,
                    "cancel_at_period_end": false,
                    "metadata": {
                        "organization_id": org.id.to_string(),
                        "plan_name": "Contrato Enterprise Negociado"
                    }
                }
            }
        });
        let created_bytes = serde_json::to_vec(&created_payload).unwrap();
        let res = process_stripe_webhook_payload(&pool, &cache, &created_bytes)
            .await
            .unwrap();
        assert_eq!(res["status"], "processed");
        assert_eq!(res["duplicate"], false);

        let active_sub = get_organization_subscription(&pool, &cache, org.id)
            .await
            .unwrap();
        assert!(active_sub.is_active());
        assert_eq!(active_sub.parsed_status(), SubscriptionStatus::Active);
        assert_eq!(active_sub.stripe_customer_id.as_deref(), Some("cus_123"));
        assert_eq!(
            active_sub.stripe_subscription_id.as_deref(),
            Some("sub_123")
        );
        assert_eq!(
            active_sub.plan_name.as_deref(),
            Some("Contrato Enterprise Negociado")
        );

        // 2. Evento duplicado deve ser ignorado com idempotência
        let dup_res = process_stripe_webhook_payload(&pool, &cache, &created_bytes)
            .await
            .unwrap();
        assert_eq!(dup_res["duplicate"], true);

        // 3. invoice.payment_failed resolve a organização apenas via stripe_customer_id
        let failed_payload = serde_json::json!({
            "id": "evt_invoice_failed_1",
            "type": "invoice.payment_failed",
            "created": 1760000100,
            "data": {
                "object": {
                    "id": "in_123",
                    "customer": "cus_123",
                    "subscription": "sub_123"
                }
            }
        });
        process_stripe_webhook_payload(
            &pool,
            &cache,
            &serde_json::to_vec(&failed_payload).unwrap(),
        )
        .await
        .unwrap();

        let past_due = get_organization_subscription(&pool, &cache, org.id)
            .await
            .unwrap();
        assert_eq!(past_due.parsed_status(), SubscriptionStatus::PastDue);
        assert!(!past_due.is_active());

        // 4. customer.subscription.deleted resolve apenas via stripe_subscription_id
        let deleted_payload = serde_json::json!({
            "id": "evt_sub_deleted_1",
            "type": "customer.subscription.deleted",
            "created": 1760000200,
            "data": {
                "object": {
                    "id": "sub_123",
                    "customer": "cus_123",
                    "status": "canceled",
                    "canceled_at": 1760000200,
                    "cancel_at_period_end": false
                }
            }
        });
        process_stripe_webhook_payload(
            &pool,
            &cache,
            &serde_json::to_vec(&deleted_payload).unwrap(),
        )
        .await
        .unwrap();

        let canceled = get_organization_subscription(&pool, &cache, org.id)
            .await
            .unwrap();
        assert_eq!(canceled.parsed_status(), SubscriptionStatus::Canceled);
        assert!(!canceled.is_active());

        let logged_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stripe_webhook_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(logged_events, 3);
    }
}
