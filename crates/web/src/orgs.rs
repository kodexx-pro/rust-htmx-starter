use std::time::Duration;

use anyhow::Context;
use askama::Template;
use axum::{
    Form,
    extract::{FromRequestParts, OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use domain::{
    DomainError, Organization, OrganizationRole, User, normalize_email,
    normalize_organization_slug, validate_organization_name,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    AppState,
    analytics::VISITOR_COOKIE,
    auth::{AuthRedirect, AuthenticatedSession, CurrentUser},
    billing::{OrganizationSubscription, get_organization_subscription},
    cache::PgCache,
    error::{AppError, HtmlTemplate},
    i18n::{Locale, Translations, safe_return_to},
    jobs::{OrgInvitePayload, QUEUE_ORG_INVITE, enqueue_transactional},
};

pub const ACTIVE_ORG_COOKIE: &str = "org_id";
const USER_ORGS_CACHE_TTL: Duration = Duration::from_secs(300);

fn user_orgs_cache_key(user_id: Uuid) -> String {
    format!("user_orgs:{user_id}")
}

pub async fn invalidate_user_orgs_cache(cache: &PgCache, user_id: Uuid) {
    let _ = cache.delete(&user_orgs_cache_key(user_id)).await;
}

pub fn set_active_org_cookie(jar: SignedCookieJar, org_id: Uuid) -> SignedCookieJar {
    let cookie = Cookie::build((ACTIVE_ORG_COOKIE, org_id.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    jar.add(cookie)
}

pub fn hash_invite_token(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    hex::encode(digest)
}

#[derive(Serialize, Deserialize)]
struct CachedOrganization {
    id: Uuid,
    name: String,
    slug: String,
    role: String,
}

impl TryFrom<CachedOrganization> for Organization {
    type Error = anyhow::Error;

    fn try_from(value: CachedOrganization) -> Result<Self, Self::Error> {
        let role = OrganizationRole::parse(&value.role)
            .context("Papel organizacional inválido no cache")?;
        Ok(Self {
            id: value.id,
            name: value.name,
            slug: value.slug,
            role,
        })
    }
}

impl From<&Organization> for CachedOrganization {
    fn from(value: &Organization) -> Self {
        Self {
            id: value.id,
            name: value.name.clone(),
            slug: value.slug.clone(),
            role: value.role.as_str().to_string(),
        }
    }
}

#[derive(FromRow)]
struct OrganizationRow {
    id: Uuid,
    name: String,
    slug: String,
    role: String,
}

pub async fn list_user_organizations(
    db: &PgPool,
    cache: &PgCache,
    user_id: Uuid,
) -> anyhow::Result<Vec<Organization>> {
    let cache_key = user_orgs_cache_key(user_id);
    if let Ok(Some(cached)) = cache.get::<Vec<CachedOrganization>>(&cache_key).await
        && let Ok(orgs) = cached
            .into_iter()
            .map(Organization::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
    {
        return Ok(orgs);
    }

    let rows = sqlx::query_as::<_, OrganizationRow>(
        r#"
        SELECT o.id, o.name, o.slug, m.role
        FROM organization_members m
        JOIN organizations o ON o.id = m.organization_id
        WHERE m.user_id = $1
        ORDER BY m.created_at ASC, o.created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .context("Falha ao listar organizações do usuário")?;

    let orgs = rows
        .into_iter()
        .map(|row| {
            let role = OrganizationRole::parse(&row.role)
                .context("Papel organizacional inválido no banco")?;
            Ok(Organization {
                id: row.id,
                name: row.name,
                slug: row.slug,
                role,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let cached_payload: Vec<CachedOrganization> =
        orgs.iter().map(CachedOrganization::from).collect();
    let _ = cache
        .set(&cache_key, &cached_payload, Some(USER_ORGS_CACHE_TTL))
        .await;

    Ok(orgs)
}

pub fn pick_active_organization(
    orgs: &[Organization],
    jar: &SignedCookieJar,
) -> Option<Organization> {
    if let Some(cookie) = jar.get(ACTIVE_ORG_COOKIE)
        && let Ok(requested_id) = Uuid::parse_str(cookie.value())
        && let Some(found) = orgs.iter().find(|o| o.id == requested_id)
    {
        return Some(found.clone());
    }
    orgs.first().cloned()
}

pub async fn resolve_active_organization_id(
    db: &PgPool,
    cache: &PgCache,
    jar: &SignedCookieJar,
    user_id: Uuid,
) -> Option<Uuid> {
    let orgs = list_user_organizations(db, cache, user_id).await.ok()?;
    pick_active_organization(&orgs, jar).map(|o| o.id)
}

pub async fn post_auth_redirect_path(
    db: &PgPool,
    cache: &PgCache,
    user_id: Uuid,
) -> anyhow::Result<&'static str> {
    if list_user_organizations(db, cache, user_id)
        .await?
        .is_empty()
    {
        Ok("/onboarding")
    } else {
        Ok("/dashboard")
    }
}

pub struct OrgContext {
    pub user: User,
    #[allow(dead_code)]
    pub session_id: String,
    pub organization: Organization,
    pub all_organizations: Vec<Organization>,
    pub subscription: OrganizationSubscription,
}

#[allow(dead_code)]
impl OrgContext {
    pub fn role(&self) -> OrganizationRole {
        self.organization.role
    }

    pub fn require_admin(&self) -> Result<(), DomainError> {
        if self.organization.role.can_manage_members() {
            Ok(())
        } else {
            Err(DomainError::Forbidden)
        }
    }

    pub fn require_owner(&self) -> Result<(), DomainError> {
        if self.organization.role.is_owner() {
            Ok(())
        } else {
            Err(DomainError::Forbidden)
        }
    }

    pub fn require_active_subscription(&self) -> Result<(), DomainError> {
        if self.subscription.is_active() {
            Ok(())
        } else {
            Err(DomainError::ActiveSubscriptionRequired)
        }
    }
}

pub enum OrgRejection {
    Auth(AuthRedirect),
    NeedsOnboarding { is_htmx: bool },
    Unexpected(AppError),
}

impl IntoResponse for OrgRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(r) => r.into_response(),
            Self::NeedsOnboarding { is_htmx } => {
                if is_htmx {
                    (StatusCode::CONFLICT, [("HX-Redirect", "/onboarding")]).into_response()
                } else {
                    Redirect::to("/onboarding").into_response()
                }
            }
            Self::Unexpected(err) => err.into_response(),
        }
    }
}

impl FromRequestParts<AppState> for OrgContext {
    type Rejection = OrgRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = AuthenticatedSession::from_request_parts(parts, state)
            .await
            .map_err(OrgRejection::Auth)?;

        let is_htmx = parts.headers.contains_key("hx-request");
        let all_organizations = list_user_organizations(&state.db, &state.cache, session.user.id)
            .await
            .map_err(|e| OrgRejection::Unexpected(AppError::Unexpected(e)))?;

        if all_organizations.is_empty() {
            return Err(OrgRejection::NeedsOnboarding { is_htmx });
        }

        let jar = SignedCookieJar::from_headers(&parts.headers, state.cookie_key.clone());
        let organization = pick_active_organization(&all_organizations, &jar)
            .ok_or(OrgRejection::NeedsOnboarding { is_htmx })?;

        let subscription = get_organization_subscription(&state.db, &state.cache, organization.id)
            .await
            .map_err(|e| OrgRejection::Unexpected(AppError::Unexpected(e)))?;

        Ok(Self {
            user: session.user,
            session_id: session.session_id,
            organization,
            all_organizations,
            subscription,
        })
    }
}

pub async fn create_organization_for_owner(
    db: &PgPool,
    cache: &PgCache,
    owner_id: Uuid,
    raw_name: &str,
    raw_slug: &str,
) -> Result<Organization, AppError> {
    let name = validate_organization_name(raw_name)?;
    let slug = normalize_organization_slug(raw_slug)?;
    let org_id = Uuid::new_v4();

    let mut tx = db
        .begin()
        .await
        .context("Falha ao abrir transação de organização")?;

    let insert_org = sqlx::query(
        r#"
        INSERT INTO organizations (id, name, slug, created_by)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(org_id)
    .bind(&name)
    .bind(&slug)
    .bind(owner_id)
    .execute(&mut *tx)
    .await;

    if let Err(err) = insert_org {
        if let sqlx::Error::Database(db_err) = &err
            && db_err.code().as_deref() == Some("23505")
        {
            return Err(DomainError::OrganizationSlugTaken.into());
        }
        return Err(anyhow::Error::from(err)
            .context("Falha ao criar organização")
            .into());
    }

    sqlx::query(
        r#"
        INSERT INTO organization_members (organization_id, user_id, role)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(org_id)
    .bind(owner_id)
    .bind(OrganizationRole::Owner.as_str())
    .execute(&mut *tx)
    .await
    .context("Falha ao vincular criador à organização")?;

    tx.commit()
        .await
        .context("Falha ao confirmar criação da organização")?;

    invalidate_user_orgs_cache(cache, owner_id).await;

    Ok(Organization {
        id: org_id,
        name,
        slug,
        role: OrganizationRole::Owner,
    })
}

#[derive(Template)]
#[template(path = "onboarding.html")]
pub struct OnboardingTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub user: User,
    pub verified_just_now: bool,
}

#[derive(Deserialize)]
pub struct OnboardingQuery {
    pub verified: Option<String>,
}

pub async fn onboarding_page(
    CurrentUser(user): CurrentUser,
    State(state): State<AppState>,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<OnboardingQuery>,
) -> Result<Response, AppError> {
    let orgs = list_user_organizations(&state.db, &state.cache, user.id).await?;
    if !orgs.is_empty() {
        return Ok(Redirect::to("/dashboard").into_response());
    }

    Ok(HtmlTemplate(OnboardingTemplate {
        locale,
        t: locale.translations(),
        return_to: uri.to_string(),
        user,
        verified_just_now: q.verified.is_some(),
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct OnboardingForm {
    pub name: String,
    pub slug: String,
}

pub async fn onboarding_submit(
    CurrentUser(user): CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<OnboardingForm>,
) -> Result<Response, AppError> {
    let org =
        create_organization_for_owner(&state.db, &state.cache, user.id, &form.name, &form.slug)
            .await?;
    let jar = set_active_org_cookie(jar, org.id);

    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user.id),
        Some(org.id),
        "org.created",
        "/onboarding",
        serde_json::json!({ "slug": org.slug }),
    );

    if headers.contains_key("hx-request") {
        Ok((jar, [("HX-Redirect", "/dashboard")]).into_response())
    } else {
        Ok((jar, Redirect::to("/dashboard")).into_response())
    }
}

#[derive(Deserialize)]
pub struct SwitchOrgForm {
    pub organization_id: Uuid,
    pub return_to: Option<String>,
}

pub async fn switch_organization(
    CurrentUser(user): CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<SwitchOrgForm>,
) -> Result<Response, AppError> {
    let orgs = list_user_organizations(&state.db, &state.cache, user.id).await?;
    let Some(target) = orgs.into_iter().find(|o| o.id == form.organization_id) else {
        return Err(DomainError::Forbidden.into());
    };

    let jar = set_active_org_cookie(jar, target.id);
    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user.id),
        Some(target.id),
        "org.switched",
        "/organizations/switch",
        serde_json::json!({ "slug": target.slug }),
    );

    let redirect_to = form
        .return_to
        .as_deref()
        .map(safe_return_to)
        .filter(|p| *p != "/login")
        .unwrap_or("/dashboard");

    if headers.contains_key("hx-request") {
        Ok((jar, [("HX-Redirect", redirect_to)]).into_response())
    } else {
        Ok((jar, Redirect::to(redirect_to)).into_response())
    }
}

pub async fn create_organization_from_dashboard(
    CurrentUser(user): CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<OnboardingForm>,
) -> Result<Response, AppError> {
    let org =
        create_organization_for_owner(&state.db, &state.cache, user.id, &form.name, &form.slug)
            .await?;
    let jar = set_active_org_cookie(jar, org.id);

    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user.id),
        Some(org.id),
        "org.created",
        "/organizations",
        serde_json::json!({ "slug": org.slug }),
    );

    if headers.contains_key("hx-request") {
        Ok((jar, [("HX-Redirect", "/organizations?saved=created")]).into_response())
    } else {
        Ok((jar, Redirect::to("/organizations?saved=created")).into_response())
    }
}

#[derive(Debug, FromRow)]
struct MemberRow {
    user_id: Uuid,
    name: String,
    email: String,
    role: String,
    joined_at: String,
}

pub struct OrganizationMemberView {
    pub user_id: Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub role_label: &'static str,
    pub joined_at: String,
    pub is_owner: bool,
    pub is_self: bool,
}

#[derive(Debug, FromRow)]
struct InviteRow {
    id: Uuid,
    email: String,
    role: String,
    expires_at: String,
}

pub struct OrganizationInviteView {
    pub id: Uuid,
    pub email: String,
    pub role_label: &'static str,
    pub expires_at: String,
}

#[derive(Deserialize)]
pub struct OrgsPageQuery {
    pub saved: Option<String>,
}

#[derive(Template)]
#[template(path = "organizations.html")]
pub struct OrganizationsTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub user: User,
    pub organization: Organization,
    pub all_organizations: Vec<Organization>,
    pub can_manage_members: bool,
    pub can_manage_roles: bool,
    pub members: Vec<OrganizationMemberView>,
    pub pending_invites: Vec<OrganizationInviteView>,
    pub flash_message: Option<&'static str>,
}

pub fn role_label(role: OrganizationRole, t: &'static Translations) -> &'static str {
    match role {
        OrganizationRole::Owner => t.role_owner,
        OrganizationRole::Admin => t.role_admin,
        OrganizationRole::Member => t.role_member,
    }
}

pub async fn organizations_page(
    ctx: OrgContext,
    State(state): State<AppState>,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<OrgsPageQuery>,
) -> Result<Response, AppError> {
    let t = locale.translations();

    let member_rows = sqlx::query_as::<_, MemberRow>(
        r#"
        SELECT
            m.user_id,
            u.name,
            u.email,
            m.role,
            TO_CHAR(m.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS joined_at
        FROM organization_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.organization_id = $1
        ORDER BY
            CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
            m.created_at ASC
        "#,
    )
    .bind(ctx.organization.id)
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar membros da organização")?;

    let members = member_rows
        .into_iter()
        .map(|row| {
            let parsed = OrganizationRole::parse(&row.role).unwrap_or(OrganizationRole::Member);
            OrganizationMemberView {
                user_id: row.user_id,
                name: row.name,
                email: row.email,
                role: row.role,
                role_label: role_label(parsed, t),
                joined_at: row.joined_at,
                is_owner: parsed.is_owner(),
                is_self: row.user_id == ctx.user.id,
            }
        })
        .collect();

    let invite_rows = sqlx::query_as::<_, InviteRow>(
        r#"
        SELECT
            id,
            email,
            role,
            TO_CHAR(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS expires_at
        FROM organization_invites
        WHERE organization_id = $1
          AND accepted_at IS NULL
          AND expires_at > NOW()
        ORDER BY created_at DESC
        "#,
    )
    .bind(ctx.organization.id)
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar convites pendentes")?;

    let pending_invites = invite_rows
        .into_iter()
        .map(|row| {
            let parsed = OrganizationRole::parse(&row.role).unwrap_or(OrganizationRole::Member);
            OrganizationInviteView {
                id: row.id,
                email: row.email,
                role_label: role_label(parsed, t),
                expires_at: row.expires_at,
            }
        })
        .collect();

    let flash_message = match query.saved.as_deref() {
        Some("invite_sent") => Some(t.org_invite_sent),
        Some("invite_revoked") => Some(t.org_invite_revoked),
        Some("member_updated") => Some(t.org_member_updated),
        Some("member_removed") => Some(t.org_member_removed),
        Some("created") => Some(t.org_created_banner),
        _ => None,
    };

    Ok(HtmlTemplate(OrganizationsTemplate {
        locale,
        t,
        return_to: uri.to_string(),
        user: ctx.user.clone(),
        can_manage_members: ctx.organization.role.can_manage_members(),
        can_manage_roles: ctx.organization.role.can_manage_roles(),
        organization: ctx.organization,
        all_organizations: ctx.all_organizations,
        members,
        pending_invites,
        flash_message,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct CreateInviteForm {
    pub email: String,
    pub role: String,
}

pub async fn create_organization_invite(
    db: &PgPool,
    app_url: &str,
    org: &Organization,
    inviter: &User,
    raw_email: &str,
    raw_role: &str,
    locale: Locale,
) -> Result<String, AppError> {
    if !org.role.can_manage_members() {
        return Err(DomainError::Forbidden.into());
    }
    let target_role = OrganizationRole::parse(raw_role.trim())
        .filter(|r| org.role.can_invite_role(*r))
        .ok_or(DomainError::Forbidden)?;

    let email = normalize_email(raw_email)?;

    let mut tx = db
        .begin()
        .await
        .context("Falha ao abrir transação de convite")?;

    let already_member: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM organization_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.organization_id = $1 AND LOWER(u.email) = $2
        )
        "#,
    )
    .bind(org.id)
    .bind(&email)
    .fetch_one(&mut *tx)
    .await
    .context("Falha ao verificar membro existente")?;

    if already_member {
        return Err(DomainError::InviteAlreadyMember.into());
    }

    sqlx::query(
        r#"
        DELETE FROM organization_invites
        WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL
        "#,
    )
    .bind(org.id)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .context("Falha ao substituir convite anterior")?;

    let raw_token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let token_hash = hash_invite_token(&raw_token);
    let invite_id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO organization_invites (id, organization_id, email, role, token_hash, invited_by_user_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '7 days')
        "#,
    )
    .bind(invite_id)
    .bind(org.id)
    .bind(&email)
    .bind(target_role.as_str())
    .bind(&token_hash)
    .bind(inviter.id)
    .execute(&mut *tx)
    .await
    .context("Falha ao gravar convite da organização")?;

    let accept_url = format!(
        "{}/invites/accept?token={}&locale={}",
        app_url.trim_end_matches('/'),
        raw_token,
        locale.code()
    );
    let localized_role = role_label(target_role, locale.translations()).to_string();

    enqueue_transactional(
        &mut tx,
        QUEUE_ORG_INVITE,
        &OrgInvitePayload {
            to: email,
            organization_name: org.name.clone(),
            inviter_name: inviter.name.clone(),
            role: localized_role,
            accept_url,
            locale,
        },
    )
    .await?;

    tx.commit()
        .await
        .context("Falha ao confirmar envio do convite")?;

    Ok(raw_token)
}

pub async fn create_invite(
    ctx: OrgContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<CreateInviteForm>,
) -> Result<Response, AppError> {
    ctx.require_admin()?;
    create_organization_invite(
        &state.db,
        &state.app_url,
        &ctx.organization,
        &ctx.user,
        &form.email,
        &form.role,
        locale,
    )
    .await?;

    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(ctx.user.id),
        Some(ctx.organization.id),
        "org.invite_sent",
        "/organizations/invites",
        serde_json::json!({ "role": form.role }),
    );

    if headers.contains_key("hx-request") {
        Ok(([("HX-Redirect", "/organizations?saved=invite_sent")]).into_response())
    } else {
        Ok(Redirect::to("/organizations?saved=invite_sent").into_response())
    }
}

pub async fn revoke_invite(
    ctx: OrgContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<Uuid>,
) -> Result<Response, AppError> {
    ctx.require_admin()?;

    sqlx::query(
        r#"
        DELETE FROM organization_invites
        WHERE id = $1 AND organization_id = $2 AND accepted_at IS NULL
        "#,
    )
    .bind(invite_id)
    .bind(ctx.organization.id)
    .execute(&state.db)
    .await
    .context("Falha ao revogar convite")?;

    if headers.contains_key("hx-request") {
        Ok(([("HX-Redirect", "/organizations?saved=invite_revoked")]).into_response())
    } else {
        Ok(Redirect::to("/organizations?saved=invite_revoked").into_response())
    }
}

#[derive(Deserialize)]
pub struct UpdateMemberRoleForm {
    pub role: String,
}

pub async fn update_member_role_for_org(
    db: &PgPool,
    cache: &PgCache,
    actor_role: OrganizationRole,
    organization_id: Uuid,
    target_user_id: Uuid,
    raw_role: &str,
) -> Result<(), AppError> {
    if !actor_role.can_manage_roles() {
        return Err(DomainError::Forbidden.into());
    }
    let next_role = OrganizationRole::parse(raw_role.trim())
        .filter(|r| !r.is_owner())
        .ok_or(DomainError::CannotModifyOwner)?;

    let current_role_raw: Option<String> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(target_user_id)
    .fetch_optional(db)
    .await
    .context("Falha ao consultar papel do membro")?;

    let Some(current_role_raw) = current_role_raw else {
        return Err(DomainError::Forbidden.into());
    };
    if current_role_raw == OrganizationRole::Owner.as_str() {
        return Err(DomainError::CannotModifyOwner.into());
    }

    sqlx::query(
        "UPDATE organization_members SET role = $1 WHERE organization_id = $2 AND user_id = $3",
    )
    .bind(next_role.as_str())
    .bind(organization_id)
    .bind(target_user_id)
    .execute(db)
    .await
    .context("Falha ao atualizar papel do membro")?;

    invalidate_user_orgs_cache(cache, target_user_id).await;
    Ok(())
}

pub async fn update_member_role(
    ctx: OrgContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_user_id): Path<Uuid>,
    Form(form): Form<UpdateMemberRoleForm>,
) -> Result<Response, AppError> {
    ctx.require_owner()?;
    update_member_role_for_org(
        &state.db,
        &state.cache,
        ctx.role(),
        ctx.organization.id,
        target_user_id,
        &form.role,
    )
    .await?;

    if headers.contains_key("hx-request") {
        Ok(([("HX-Redirect", "/organizations?saved=member_updated")]).into_response())
    } else {
        Ok(Redirect::to("/organizations?saved=member_updated").into_response())
    }
}

pub async fn remove_member_from_org(
    db: &PgPool,
    cache: &PgCache,
    actor_role: OrganizationRole,
    organization_id: Uuid,
    target_user_id: Uuid,
) -> Result<(), AppError> {
    if !actor_role.can_manage_members() {
        return Err(DomainError::Forbidden.into());
    }

    let current_role_raw: Option<String> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(target_user_id)
    .fetch_optional(db)
    .await
    .context("Falha ao consultar membro para remoção")?;

    let Some(current_role_raw) = current_role_raw else {
        return Err(DomainError::Forbidden.into());
    };
    let target_role =
        OrganizationRole::parse(&current_role_raw).unwrap_or(OrganizationRole::Member);
    if target_role.is_owner() {
        return Err(DomainError::CannotModifyOwner.into());
    }
    if target_role == OrganizationRole::Admin && !actor_role.is_owner() {
        return Err(DomainError::Forbidden.into());
    }

    sqlx::query("DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2")
        .bind(organization_id)
        .bind(target_user_id)
        .execute(db)
        .await
        .context("Falha ao remover membro da organização")?;

    invalidate_user_orgs_cache(cache, target_user_id).await;
    Ok(())
}

pub async fn remove_member(
    ctx: OrgContext,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(target_user_id): Path<Uuid>,
) -> Result<Response, AppError> {
    ctx.require_admin()?;
    remove_member_from_org(
        &state.db,
        &state.cache,
        ctx.role(),
        ctx.organization.id,
        target_user_id,
    )
    .await?;

    if headers.contains_key("hx-request") {
        Ok(([("HX-Redirect", "/organizations?saved=member_removed")]).into_response())
    } else {
        Ok(Redirect::to("/organizations?saved=member_removed").into_response())
    }
}

#[derive(Deserialize)]
pub struct AcceptInviteQuery {
    pub token: Option<String>,
}

#[derive(Debug, FromRow)]
struct PendingInviteRow {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    organization_slug: String,
    email: String,
    role: String,
}

#[derive(Template)]
#[template(path = "invite_accept.html")]
pub struct InviteAcceptTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub user: User,
    pub token: String,
    pub invite_valid: bool,
    pub organization_name: String,
    pub organization_slug: String,
    pub invited_email: String,
    pub role_label: &'static str,
    pub email_matches: bool,
}

fn encode_query_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

pub async fn accept_invite_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AcceptInviteQuery>,
) -> Result<Response, AppError> {
    let token = query.token.unwrap_or_default();
    let user = crate::auth::try_resolve_session_user(&headers, &state).await;
    let Some(user) = user else {
        let next_path = if token.is_empty() {
            "/invites/accept".to_string()
        } else {
            format!("/invites/accept?token={}", encode_query_component(&token))
        };
        let login_url = format!("/login?next={}", encode_query_component(&next_path));
        return Ok(Redirect::to(&login_url).into_response());
    };

    let t = locale.translations();
    let row = if token.is_empty() {
        None
    } else {
        let token_hash = hash_invite_token(&token);
        sqlx::query_as::<_, PendingInviteRow>(
            r#"
            SELECT
                i.id,
                i.organization_id,
                o.name AS organization_name,
                o.slug AS organization_slug,
                i.email,
                i.role
            FROM organization_invites i
            JOIN organizations o ON o.id = i.organization_id
            WHERE i.token_hash = $1
              AND i.accepted_at IS NULL
              AND i.expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&state.db)
        .await
        .context("Falha ao consultar convite")?
    };

    match row {
        Some(inv) => {
            let parsed_role =
                OrganizationRole::parse(&inv.role).unwrap_or(OrganizationRole::Member);
            let email_matches = user.email.eq_ignore_ascii_case(&inv.email);
            Ok(HtmlTemplate(InviteAcceptTemplate {
                locale,
                t,
                return_to: uri.to_string(),
                user,
                token,
                invite_valid: true,
                organization_name: inv.organization_name,
                organization_slug: inv.organization_slug,
                invited_email: inv.email,
                role_label: role_label(parsed_role, t),
                email_matches,
            })
            .into_response())
        }
        None => Ok((
            StatusCode::NOT_FOUND,
            HtmlTemplate(InviteAcceptTemplate {
                locale,
                t,
                return_to: uri.to_string(),
                user,
                token,
                invite_valid: false,
                organization_name: String::new(),
                organization_slug: String::new(),
                invited_email: String::new(),
                role_label: t.role_member,
                email_matches: false,
            }),
        )
            .into_response()),
    }
}

#[derive(Deserialize)]
pub struct AcceptInviteForm {
    pub token: String,
}

pub async fn accept_invite_for_user(
    db: &PgPool,
    cache: &PgCache,
    user: &User,
    raw_token: &str,
) -> Result<Uuid, AppError> {
    let token_hash = hash_invite_token(raw_token.trim());
    let mut tx = db
        .begin()
        .await
        .context("Falha ao abrir transação de aceite de convite")?;

    let invite = sqlx::query_as::<_, PendingInviteRow>(
        r#"
        SELECT
            i.id,
            i.organization_id,
            o.name AS organization_name,
            o.slug AS organization_slug,
            i.email,
            i.role
        FROM organization_invites i
        JOIN organizations o ON o.id = i.organization_id
        WHERE i.token_hash = $1
          AND i.accepted_at IS NULL
          AND i.expires_at > NOW()
        FOR UPDATE OF i
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await
    .context("Falha ao validar token de convite")?;

    let Some(invite) = invite else {
        return Err(DomainError::InvalidOrExpiredToken.into());
    };

    if !user.email.eq_ignore_ascii_case(&invite.email) {
        return Err(DomainError::InviteEmailMismatch.into());
    }

    sqlx::query("UPDATE organization_invites SET accepted_at = NOW() WHERE id = $1")
        .bind(invite.id)
        .execute(&mut *tx)
        .await
        .context("Falha ao marcar convite como aceito")?;

    sqlx::query(
        r#"
        INSERT INTO organization_members (organization_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (organization_id, user_id) DO NOTHING
        "#,
    )
    .bind(invite.organization_id)
    .bind(user.id)
    .bind(&invite.role)
    .execute(&mut *tx)
    .await
    .context("Falha ao adicionar usuário à organização")?;

    tx.commit()
        .await
        .context("Falha ao confirmar aceite do convite")?;

    invalidate_user_orgs_cache(cache, user.id).await;
    Ok(invite.organization_id)
}

pub async fn accept_invite_submit(
    CurrentUser(user): CurrentUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<AcceptInviteForm>,
) -> Result<Response, AppError> {
    let org_id = accept_invite_for_user(&state.db, &state.cache, &user, &form.token).await?;
    let jar = set_active_org_cookie(jar, org_id);

    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user.id),
        Some(org_id),
        "org.invite_accepted",
        "/invites/accept",
        serde_json::json!({}),
    );

    if headers.contains_key("hx-request") {
        Ok((jar, [("HX-Redirect", "/dashboard")]).into_response())
    } else {
        Ok((jar, Redirect::to("/dashboard")).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn onboarding_creates_organization_with_owner_and_rejects_duplicate_slug(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let cache = PgCache::new(pool.clone());
        let user_id = Uuid::new_v4();
        let second_user_id = Uuid::new_v4();

        sqlx::query("INSERT INTO users (id, email, name) VALUES ($1, $2, $3), ($4, $5, $6)")
            .bind(user_id)
            .bind("founder@exemplo.com")
            .bind("Founder")
            .bind(second_user_id)
            .bind("other@exemplo.com")
            .bind("Other")
            .execute(&pool)
            .await?;

        assert_eq!(
            post_auth_redirect_path(&pool, &cache, user_id).await?,
            "/onboarding"
        );

        let created = create_organization_for_owner(
            &pool,
            &cache,
            user_id,
            "  Acme Studio  ",
            "  Acme-Studio ",
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        assert_eq!(created.name, "Acme Studio");
        assert_eq!(created.slug, "acme-studio");
        assert_eq!(created.role, OrganizationRole::Owner);
        assert_eq!(
            post_auth_redirect_path(&pool, &cache, user_id).await?,
            "/dashboard"
        );

        let orgs = list_user_organizations(&pool, &cache, user_id).await?;
        assert_eq!(orgs, vec![created]);

        let duplicate = create_organization_for_owner(
            &pool,
            &cache,
            second_user_id,
            "Outra Empresa",
            "acme-studio",
        )
        .await;
        assert!(matches!(
            duplicate,
            Err(AppError::Domain(DomainError::OrganizationSlugTaken))
        ));

        Ok(())
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn invites_rbac_and_org_switching_lifecycle(pool: PgPool) -> anyhow::Result<()> {
        let boss = pgboss::Client::with_pool(pool.clone()).await?;
        boss.create_standard_queue(QUEUE_ORG_INVITE).await?;
        let cache = PgCache::new(pool.clone());

        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let stranger_id = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO users (id, email, name) VALUES ($1, $2, $3), ($4, $5, $6), ($7, $8, $9)",
        )
        .bind(owner_id)
        .bind("owner@acme.com")
        .bind("Owner")
        .bind(member_id)
        .bind("colega@acme.com")
        .bind("Colega")
        .bind(stranger_id)
        .bind("stranger@acme.com")
        .bind("Stranger")
        .execute(&pool)
        .await?;

        let org_a = create_organization_for_owner(&pool, &cache, owner_id, "Acme A", "acme-a")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let org_b = create_organization_for_owner(&pool, &cache, owner_id, "Acme B", "acme-b")
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let owner_user = User {
            id: owner_id,
            email: "owner@acme.com".into(),
            name: "Owner".into(),
            email_verified: true,
            is_platform_admin: false,
        };
        let member_user = User {
            id: member_id,
            email: "colega@acme.com".into(),
            name: "Colega".into(),
            email_verified: true,
            is_platform_admin: false,
        };
        let stranger_user = User {
            id: stranger_id,
            email: "stranger@acme.com".into(),
            name: "Stranger".into(),
            email_verified: true,
            is_platform_admin: false,
        };

        // Convite grava token hash + job pgboss na mesma transação
        let raw_token = create_organization_invite(
            &pool,
            "http://localhost:3000",
            &org_a,
            &owner_user,
            "Colega@Acme.com",
            "member",
            Locale::Es,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        let job_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pgboss.job WHERE name = $1 AND data->>'to' = 'colega@acme.com'",
        )
        .bind(QUEUE_ORG_INVITE)
        .fetch_one(&pool)
        .await?;
        assert_eq!(job_count, 1);

        // E-mail diferente não consegue aceitar o convite
        let wrong_user = accept_invite_for_user(&pool, &cache, &stranger_user, &raw_token).await;
        assert!(matches!(
            wrong_user,
            Err(AppError::Domain(DomainError::InviteEmailMismatch))
        ));

        // Usuário convidado aceita e entra como member
        let joined_org_id = accept_invite_for_user(&pool, &cache, &member_user, &raw_token)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(joined_org_id, org_a.id);

        let member_orgs = list_user_organizations(&pool, &cache, member_id).await?;
        assert_eq!(member_orgs.len(), 1);
        assert_eq!(member_orgs[0].role, OrganizationRole::Member);

        // Member não tem permissão para convidar ou alterar papéis
        let member_invite = create_organization_invite(
            &pool,
            "http://localhost:3000",
            &member_orgs[0],
            &member_user,
            "x@acme.com",
            "member",
            Locale::Pt,
        )
        .await;
        assert!(matches!(
            member_invite,
            Err(AppError::Domain(DomainError::Forbidden))
        ));

        let member_role_change = update_member_role_for_org(
            &pool,
            &cache,
            OrganizationRole::Member,
            org_a.id,
            owner_id,
            "member",
        )
        .await;
        assert!(matches!(
            member_role_change,
            Err(AppError::Domain(DomainError::Forbidden))
        ));

        // Owner promove member -> admin e depois não pode ser rebaixado
        update_member_role_for_org(
            &pool,
            &cache,
            OrganizationRole::Owner,
            org_a.id,
            member_id,
            "admin",
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        let updated_orgs = list_user_organizations(&pool, &cache, member_id).await?;
        assert_eq!(updated_orgs[0].role, OrganizationRole::Admin);

        let demote_owner = update_member_role_for_org(
            &pool,
            &cache,
            OrganizationRole::Owner,
            org_a.id,
            owner_id,
            "member",
        )
        .await;
        assert!(matches!(
            demote_owner,
            Err(AppError::Domain(DomainError::CannotModifyOwner))
        ));

        // Troca de organização via cookie assinado
        let key = axum_extra::extract::cookie::Key::from(&[9u8; 64]);
        let jar = SignedCookieJar::new(key);
        let jar = set_active_org_cookie(jar, org_b.id);
        let owner_orgs = list_user_organizations(&pool, &cache, owner_id).await?;
        assert_eq!(
            pick_active_organization(&owner_orgs, &jar).unwrap().id,
            org_b.id
        );

        Ok(())
    }
}
