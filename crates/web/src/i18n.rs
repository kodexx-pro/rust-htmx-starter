use std::convert::Infallible;

use axum::{
    Form,
    extract::{FromRequestParts, Query, Request},
    http::{HeaderMap, HeaderValue, Method, Uri, header, request::Parts, uri::PathAndQuery},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

use crate::error;

const LOCALE_COOKIE: &str = "locale";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    #[default]
    Pt,
    Es,
}

impl Locale {
    pub fn code(self) -> &'static str {
        match self {
            Self::Pt => "pt",
            Self::Es => "es",
        }
    }

    pub fn html_lang(self) -> &'static str {
        match self {
            Self::Pt => "pt-BR",
            Self::Es => "es",
        }
    }

    pub fn is_pt(self) -> bool {
        self == Self::Pt
    }

    pub fn translations(self) -> &'static Translations {
        match self {
            Self::Pt => &PORTUGUESE,
            Self::Es => &SPANISH,
        }
    }

    fn from_cookie(headers: &HeaderMap) -> Option<Self> {
        let jar = CookieJar::from_headers(headers);
        match jar.get(LOCALE_COOKIE).map(|cookie| cookie.value()) {
            Some("pt") => Some(Self::Pt),
            Some("es") => Some(Self::Es),
            _ => None,
        }
    }

    fn cookie(self) -> HeaderValue {
        match self {
            Self::Pt => HeaderValue::from_static(
                "locale=pt; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax",
            ),
            Self::Es => HeaderValue::from_static(
                "locale=es; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax",
            ),
        }
    }
}

impl<S> FromRequestParts<S> for Locale
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<Self>()
            .copied()
            .or_else(|| Self::from_cookie(&parts.headers))
            .unwrap_or_default())
    }
}

#[derive(Deserialize)]
struct EmailLinkQuery {
    locale: Option<Locale>,
}

fn email_link_locale(method: &Method, uri: &Uri) -> Option<Locale> {
    if *method != Method::GET
        || !matches!(
            uri.path(),
            "/verify-email" | "/reset-password" | "/invites/accept"
        )
    {
        return None;
    }
    Query::<EmailLinkQuery>::try_from_uri(uri).ok()?.0.locale
}

pub async fn localize(mut request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path.starts_with("/webhooks/") || path.starts_with("/analytics/") || path == "/metrics" {
        return next.run(request).await;
    }
    let cookie_locale = Locale::from_cookie(request.headers());
    let link_locale = if cookie_locale.is_none() {
        email_link_locale(request.method(), request.uri())
    } else {
        None
    };
    let locale = cookie_locale.or(link_locale).unwrap_or_default();
    let error_target = match request.uri().path() {
        "/resend-verification" | "/logout" => "#toast-container",
        "/onboarding" => "#onboarding-feedback",
        p if p.starts_with("/organizations") => "#org-feedback",
        p if p.starts_with("/invites") => "#invite-feedback",
        p if p.starts_with("/admin") => "#admin-feedback",
        _ => "#auth-feedback",
    };
    request.extensions_mut().insert(locale);
    let mut response = error::localize_response(next.run(request).await, locale, error_target);
    if link_locale.is_some() {
        response
            .headers_mut()
            .append(header::SET_COOKIE, locale.cookie());
    }
    response
}

#[derive(Deserialize)]
pub struct LanguageForm {
    locale: Locale,
    return_to: String,
}

pub fn safe_return_to(value: &str) -> &str {
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\\')
        && value.parse::<PathAndQuery>().is_ok()
        && HeaderValue::from_str(value).is_ok()
    {
        value
    } else {
        "/login"
    }
}

pub async fn set_language(Form(form): Form<LanguageForm>) -> Response {
    let mut response = Redirect::to(safe_return_to(&form.return_to)).into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, form.locale.cookie());
    response
}

pub struct Translations {
    pub language: &'static str,
    pub apply_language: &'static str,
    pub home_title: &'static str,
    pub home_description: &'static str,
    pub home_dashboard: &'static str,
    pub login_title: &'static str,
    pub login_heading: &'static str,
    pub email: &'static str,
    pub email_placeholder: &'static str,
    pub password: &'static str,
    pub forgot_password_link: &'static str,
    pub login_action: &'static str,
    pub or_text: &'static str,
    pub no_account: &'static str,
    pub create_account: &'static str,
    pub register_title: &'static str,
    pub register_heading: &'static str,
    pub name: &'static str,
    pub name_placeholder: &'static str,
    pub password_min: &'static str,
    pub register_action: &'static str,
    pub has_account: &'static str,
    pub login_link: &'static str,
    pub forgot_title: &'static str,
    pub forgot_instructions: &'static str,
    pub send_recovery_link: &'static str,
    pub back_to_login: &'static str,
    pub reset_title: &'static str,
    pub new_password: &'static str,
    pub new_password_min: &'static str,
    pub save_new_password: &'static str,
    pub dashboard_title: &'static str,
    pub brand: &'static str,
    pub logout: &'static str,
    pub verified_success: &'static str,
    pub welcome: &'static str,
    pub verified_label: &'static str,
    pub awaiting_verification: &'static str,
    pub dashboard_description: &'static str,
    pub confirm_email: &'static str,
    pub verification_sent_to: &'static str,
    pub resend_email: &'static str,
    pub password_reset_success: &'static str,
    pub verification_resent: &'static str,
    pub recovery_neutral: &'static str,
    pub invalid_credentials: &'static str,
    pub email_in_use: &'static str,
    pub required_field: &'static str,
    pub invalid_email: &'static str,
    pub invalid_name: &'static str,
    pub weak_password: &'static str,
    pub invalid_token: &'static str,
    pub internal_error: &'static str,
    pub critical_error: &'static str,
    pub bad_request: &'static str,
    pub not_found: &'static str,
    pub method_not_allowed: &'static str,
    pub request_error: &'static str,
    pub continue_with_google: &'static str,
    pub google_not_configured: &'static str,
    pub google_cancelled: &'static str,
    pub google_auth_failed: &'static str,
    pub google_unverified_email: &'static str,
    pub onboarding_title: &'static str,
    pub onboarding_heading: &'static str,
    pub onboarding_subtitle: &'static str,
    pub org_name_label: &'static str,
    pub org_name_placeholder: &'static str,
    pub org_slug_label: &'static str,
    pub org_slug_placeholder: &'static str,
    pub org_slug_hint: &'static str,
    pub create_org_action: &'static str,
    pub invalid_org_name: &'static str,
    pub invalid_org_slug: &'static str,
    pub org_slug_taken: &'static str,
    pub current_org_label: &'static str,
    pub role_owner: &'static str,
    pub role_admin: &'static str,
    pub role_member: &'static str,
    pub account_suspended: &'static str,
    pub registration_disabled: &'static str,
    pub forbidden_error: &'static str,
    pub invalid_log_filter: &'static str,
    pub maintenance_active: &'static str,
    pub admin_link: &'static str,
    pub admin_title: &'static str,
    pub admin_subtitle: &'static str,
    pub admin_back_dashboard: &'static str,
    pub admin_saved_settings: &'static str,
    pub admin_saved_user: &'static str,
    pub admin_saved_cache: &'static str,
    pub admin_saved_cron: &'static str,
    pub admin_saved_jobs: &'static str,
    pub admin_metrics_users: &'static str,
    pub admin_metrics_orgs: &'static str,
    pub admin_metrics_cache: &'static str,
    pub admin_metrics_cron: &'static str,
    pub admin_settings_heading: &'static str,
    pub admin_registration_toggle: &'static str,
    pub admin_maintenance_toggle: &'static str,
    pub admin_google_toggle: &'static str,
    pub admin_log_filter_label: &'static str,
    pub admin_save_settings: &'static str,
    pub admin_users_heading: &'static str,
    pub admin_search_placeholder: &'static str,
    pub admin_search_action: &'static str,
    pub admin_orgs_heading: &'static str,
    pub admin_ops_heading: &'static str,
    pub admin_purge_cache: &'static str,
    pub admin_clear_cache: &'static str,
    pub admin_retry_jobs: &'static str,
    pub admin_audit_heading: &'static str,
    pub admin_saved_subscription: &'static str,
    pub admin_metrics_active_subs: &'static str,
    pub admin_webhooks_heading: &'static str,
    pub sub_section_label: &'static str,
    pub sub_no_plan: &'static str,
    pub sub_period_end_label: &'static str,
    pub sub_status_active: &'static str,
    pub sub_status_trialing: &'static str,
    pub sub_status_past_due: &'static str,
    pub sub_status_canceled: &'static str,
    pub sub_status_inactive: &'static str,
    pub admin_analytics_heading: &'static str,
    pub admin_analytics_views_24h: &'static str,
    pub admin_analytics_clicks_24h: &'static str,
    pub admin_analytics_visitors_24h: &'static str,
    pub admin_analytics_avg_time: &'static str,
    pub admin_analytics_top_pages: &'static str,
    pub admin_analytics_top_clicks: &'static str,
    pub admin_analytics_locations: &'static str,
    pub admin_analytics_recent: &'static str,
    pub theme_label: &'static str,
    pub theme_auto: &'static str,
    pub theme_light: &'static str,
    pub theme_dark: &'static str,
    pub rate_limit_exceeded: &'static str,
    pub csrf_validation_failed: &'static str,
    pub invite_already_member: &'static str,
    pub invite_email_mismatch: &'static str,
    pub cannot_modify_owner: &'static str,
    pub active_subscription_required: &'static str,
    pub switch_org_action: &'static str,
    pub manage_org_link: &'static str,
    pub orgs_title: &'static str,
    pub orgs_heading: &'static str,
    pub orgs_subtitle: &'static str,
    pub org_create_new_heading: &'static str,
    pub org_members_heading: &'static str,
    pub org_invites_heading: &'static str,
    pub org_invite_email_placeholder: &'static str,
    pub org_invite_role_label: &'static str,
    pub org_invite_send: &'static str,
    pub org_invite_sent: &'static str,
    pub org_invite_revoked: &'static str,
    pub org_member_updated: &'static str,
    pub org_member_removed: &'static str,
    pub org_created_banner: &'static str,
    pub org_revoke_invite: &'static str,
    pub org_remove_member: &'static str,
    pub org_save_role: &'static str,
    pub org_no_pending_invites: &'static str,
    pub org_pending_status: &'static str,
    pub org_expires_at: &'static str,
    pub invite_accept_title: &'static str,
    pub invite_accept_heading: &'static str,
    pub invite_accept_subtitle: &'static str,
    pub invite_accept_action: &'static str,
    pub invite_logged_as: &'static str,
    pub invite_invalid_heading: &'static str,
    pub org_readonly_notice: &'static str,
}

static PORTUGUESE: Translations = Translations {
    language: "Idioma",
    apply_language: "Alterar",
    home_title: "Bem-vindo ao seu site",
    home_description: "Esta é a página inicial do seu projeto. Personalize o conteúdo para apresentar seu produto.",
    home_dashboard: "Acessar painel",
    login_title: "Entrar",
    login_heading: "Acessar conta",
    email: "E-mail",
    email_placeholder: "voce@empresa.com",
    password: "Senha",
    forgot_password_link: "Esqueceu a senha?",
    login_action: "Entrar",
    or_text: "OU",
    no_account: "Ainda não tem conta?",
    create_account: "Criar conta",
    register_title: "Criar conta",
    register_heading: "Criar nova conta",
    name: "Nome",
    name_placeholder: "Seu nome",
    password_min: "Senha (mín. 8 caracteres)",
    register_action: "Cadastrar",
    has_account: "Já possui cadastro?",
    login_link: "Fazer login",
    forgot_title: "Recuperar senha",
    forgot_instructions: "Informe seu e-mail para receber um link de redefinição.",
    send_recovery_link: "Enviar link de recuperação",
    back_to_login: "Voltar para o login",
    reset_title: "Redefinir senha",
    new_password: "Nova senha",
    new_password_min: "Nova senha (mín. 8 caracteres)",
    save_new_password: "Salvar nova senha",
    dashboard_title: "Painel",
    brand: "MeuSistema",
    logout: "Sair",
    verified_success: "E-mail confirmado com sucesso!",
    welcome: "Bem-vindo",
    verified_label: "E-mail verificado",
    awaiting_verification: "Aguardando verificação",
    dashboard_description: "Sua sessão está autenticada via cookie assinado e pronta para receber os módulos do seu produto.",
    confirm_email: "Confirme seu e-mail",
    verification_sent_to: "Enviamos um link de confirmação para",
    resend_email: "Reenviar e-mail",
    password_reset_success: "Senha redefinida com sucesso. Faça login com sua nova senha.",
    verification_resent: "Novo e-mail de confirmação enviado!",
    recovery_neutral: "Se o e-mail estiver cadastrado, enviaremos um link de recuperação em instantes.",
    invalid_credentials: "E-mail ou senha inválidos.",
    email_in_use: "Este e-mail já está cadastrado.",
    required_field: "Preencha este campo.",
    invalid_email: "Informe um endereço de e-mail válido.",
    invalid_name: "O nome precisa ter pelo menos 2 caracteres.",
    weak_password: "A senha deve ter no mínimo 8 caracteres.",
    invalid_token: "O link de verificação ou redefinição é inválido ou expirou.",
    internal_error: "Erro interno inesperado. Tente novamente em instantes.",
    critical_error: "Erro crítico.",
    bad_request: "Não foi possível processar a solicitação.",
    not_found: "Página não encontrada.",
    method_not_allowed: "Ação não permitida.",
    request_error: "Não foi possível concluir a solicitação.",
    continue_with_google: "Continuar com Google",
    google_not_configured: "O login com Google ainda não está configurado.",
    google_cancelled: "Login com Google cancelado.",
    google_auth_failed: "Não foi possível concluir a autenticação com o Google.",
    google_unverified_email: "Sua conta Google precisa ter um e-mail verificado.",
    onboarding_title: "Configurar organização",
    onboarding_heading: "Crie sua organização",
    onboarding_subtitle: "Antes de acessar o painel, informe os dados iniciais da sua organização.",
    org_name_label: "Nome da organização",
    org_name_placeholder: "Ex.: Acme Tecnologia",
    org_slug_label: "Slug da organização",
    org_slug_placeholder: "acme-tecnologia",
    org_slug_hint: "Use 3 a 50 caracteres: apenas letras minúsculas, números e hífens.",
    create_org_action: "Criar organização e continuar",
    invalid_org_name: "O nome da organização precisa ter entre 2 e 80 caracteres.",
    invalid_org_slug: "O slug deve ter entre 3 e 50 caracteres usando apenas letras minúsculas, números e hífens.",
    org_slug_taken: "Este slug já está em uso por outra organização.",
    current_org_label: "Organização ativa",
    role_owner: "Proprietário",
    role_admin: "Administrador",
    role_member: "Membro",
    account_suspended: "Esta conta foi suspensa pelos administradores da plataforma.",
    registration_disabled: "Novos cadastros estão temporariamente desabilitados.",
    forbidden_error: "Você não tem permissão para acessar esta área.",
    invalid_log_filter: "O filtro de log informado é inválido.",
    maintenance_active: "Sistema em manutenção temporária. Tente novamente em instantes.",
    admin_link: "Admin",
    admin_title: "Administração da Plataforma",
    admin_subtitle: "Controles de operação, usuários, organizações, filas, cache e tracing em tempo real.",
    admin_back_dashboard: "Voltar ao painel",
    admin_saved_settings: "Configurações e tracing atualizados com sucesso.",
    admin_saved_user: "Estado do usuário atualizado.",
    admin_saved_cache: "Operação de cache executada.",
    admin_saved_cron: "Estado do cronjob alterado.",
    admin_saved_jobs: "Jobs com falha reenfileirados.",
    admin_metrics_users: "Usuários",
    admin_metrics_orgs: "Organizações",
    admin_metrics_cache: "Entradas no Cache",
    admin_metrics_cron: "pg_cron",
    admin_settings_heading: "Controles do Sistema & Tracing",
    admin_registration_toggle: "Permitir novos cadastros públicos",
    admin_maintenance_toggle: "Modo manutenção (bloqueia rotas comuns para não-admins)",
    admin_google_toggle: "Permitir login com Google OAuth",
    admin_log_filter_label: "Filtro de tracing (RUST_LOG dinâmico)",
    admin_save_settings: "Salvar configurações",
    admin_users_heading: "Usuários",
    admin_search_placeholder: "Buscar por nome ou e-mail...",
    admin_search_action: "Buscar",
    admin_orgs_heading: "Organizações",
    admin_ops_heading: "Cache, Filas (pgboss) e Cronjobs (pg_cron)",
    admin_purge_cache: "Limpar expirados",
    admin_clear_cache: "Limpar cache (exceto sessões)",
    admin_retry_jobs: "Reenfileirar jobs falhos",
    admin_audit_heading: "Auditoria recente",
    admin_saved_subscription: "Assinatura da organização atualizada.",
    admin_metrics_active_subs: "Assinaturas ativas",
    admin_webhooks_heading: "Webhooks Stripe recentes",
    sub_section_label: "Assinatura",
    sub_no_plan: "Contrato personalizado",
    sub_period_end_label: "Ciclo até",
    sub_status_active: "Ativa",
    sub_status_trialing: "Em avaliação",
    sub_status_past_due: "Pagamento pendente",
    sub_status_canceled: "Cancelada",
    sub_status_inactive: "Sem assinatura ativa",
    admin_analytics_heading: "Analytics de Uso & Telemetria (24h / 7d)",
    admin_analytics_views_24h: "Visualizações (24h)",
    admin_analytics_clicks_24h: "Cliques (24h)",
    admin_analytics_visitors_24h: "Visitantes únicos (24h)",
    admin_analytics_avg_time: "Tempo médio ativo",
    admin_analytics_top_pages: "Páginas mais visualizadas (7d)",
    admin_analytics_top_clicks: "Cliques mais frequentes (7d)",
    admin_analytics_locations: "Localização & Fusos (7d)",
    admin_analytics_recent: "Eventos de uso recentes",
    theme_label: "Tema",
    theme_auto: "Sistema",
    theme_light: "Claro",
    theme_dark: "Escuro",
    rate_limit_exceeded: "Muitas tentativas em sequência. Aguarde um momento e tente novamente.",
    csrf_validation_failed: "Solicitação bloqueada pela proteção CSRF. Recarregue a página e tente novamente.",
    invite_already_member: "Este e-mail já pertence à organização.",
    invite_email_mismatch: "Este convite pertence a outro endereço de e-mail. Entre com a conta convidada.",
    cannot_modify_owner: "Não é possível remover ou alterar o papel do proprietário.",
    active_subscription_required: "Esta funcionalidade requer uma assinatura ativa para a organização.",
    switch_org_action: "Trocar",
    manage_org_link: "Equipe e Organizações",
    orgs_title: "Organizações e Equipe",
    orgs_heading: "Organizações e Equipe",
    orgs_subtitle: "Gerencie membros, convites, papéis de acesso e crie novas organizações.",
    org_create_new_heading: "Criar nova organização",
    org_members_heading: "Membros da organização ativa",
    org_invites_heading: "Convites pendentes",
    org_invite_email_placeholder: "colega@empresa.com",
    org_invite_role_label: "Papel",
    org_invite_send: "Enviar convite",
    org_invite_sent: "Convite enviado com sucesso!",
    org_invite_revoked: "Convite revogado.",
    org_member_updated: "Papel do membro atualizado.",
    org_member_removed: "Membro removido da organização.",
    org_created_banner: "Nova organização criada e ativada!",
    org_revoke_invite: "Revogar",
    org_remove_member: "Remover",
    org_save_role: "Salvar",
    org_no_pending_invites: "Nenhum convite pendente.",
    org_pending_status: "Pendente",
    org_expires_at: "Expira em",
    invite_accept_title: "Aceitar convite",
    invite_accept_heading: "Convite para organização",
    invite_accept_subtitle: "Você foi convidado para participar desta organização como",
    invite_accept_action: "Aceitar e entrar",
    invite_logged_as: "Conectado como",
    invite_invalid_heading: "Convite indisponível",
    org_readonly_notice: "Seu papel atual permite visualizar a equipe; apenas proprietários e administradores podem convidar ou remover membros.",
};

static SPANISH: Translations = Translations {
    language: "Idioma",
    apply_language: "Cambiar",
    home_title: "Bienvenido a tu sitio",
    home_description: "Esta es la página de inicio de tu proyecto. Personaliza el contenido para presentar tu producto.",
    home_dashboard: "Ir al panel",
    login_title: "Iniciar sesión",
    login_heading: "Acceder a la cuenta",
    email: "Correo electrónico",
    email_placeholder: "tu@empresa.com",
    password: "Contraseña",
    forgot_password_link: "¿Olvidaste tu contraseña?",
    login_action: "Iniciar sesión",
    or_text: "O",
    no_account: "¿Aún no tienes una cuenta?",
    create_account: "Crear cuenta",
    register_title: "Crear cuenta",
    register_heading: "Crear una cuenta nueva",
    name: "Nombre",
    name_placeholder: "Tu nombre",
    password_min: "Contraseña (mín. 8 caracteres)",
    register_action: "Registrarse",
    has_account: "¿Ya tienes una cuenta?",
    login_link: "Iniciar sesión",
    forgot_title: "Recuperar contraseña",
    forgot_instructions: "Introduce tu correo electrónico para recibir un enlace de restablecimiento.",
    send_recovery_link: "Enviar enlace de recuperación",
    back_to_login: "Volver al inicio de sesión",
    reset_title: "Restablecer contraseña",
    new_password: "Nueva contraseña",
    new_password_min: "Nueva contraseña (mín. 8 caracteres)",
    save_new_password: "Guardar nueva contraseña",
    dashboard_title: "Panel",
    brand: "MiSistema",
    logout: "Cerrar sesión",
    verified_success: "Correo electrónico confirmado correctamente.",
    welcome: "Te damos la bienvenida",
    verified_label: "Correo electrónico verificado",
    awaiting_verification: "Pendiente de verificación",
    dashboard_description: "Tu sesión está autenticada mediante una cookie firmada y está lista para recibir los módulos de tu producto.",
    confirm_email: "Confirma tu correo electrónico",
    verification_sent_to: "Enviamos un enlace de confirmación a",
    resend_email: "Reenviar correo",
    password_reset_success: "Contraseña restablecida correctamente. Inicia sesión con tu nueva contraseña.",
    verification_resent: "Se ha enviado un nuevo correo de confirmación.",
    recovery_neutral: "Si el correo electrónico está registrado, enviaremos un enlace de recuperación en breve.",
    invalid_credentials: "Correo electrónico o contraseña incorrectos.",
    email_in_use: "Este correo electrónico ya está registrado.",
    required_field: "Completa este campo.",
    invalid_email: "Introduce una dirección de correo electrónico válida.",
    invalid_name: "El nombre debe tener al menos 2 caracteres.",
    weak_password: "La contraseña debe tener al menos 8 caracteres.",
    invalid_token: "El enlace de verificación o restablecimiento no es válido o ha caducado.",
    internal_error: "Se produjo un error interno. Inténtalo de nuevo en unos momentos.",
    critical_error: "Error crítico.",
    bad_request: "No se pudo procesar la solicitud.",
    not_found: "Página no encontrada.",
    method_not_allowed: "Acción no permitida.",
    request_error: "No se pudo completar la solicitud.",
    continue_with_google: "Continuar con Google",
    google_not_configured: "El inicio de sesión con Google aún no está configurado.",
    google_cancelled: "Inicio de sesión con Google cancelado.",
    google_auth_failed: "No se pudo completar la autenticación con Google.",
    google_unverified_email: "Tu cuenta de Google debe tener un correo electrónico verificado.",
    onboarding_title: "Configurar organización",
    onboarding_heading: "Crea tu organización",
    onboarding_subtitle: "Antes de acceder al panel, introduce los datos iniciales de tu organización.",
    org_name_label: "Nombre de la organización",
    org_name_placeholder: "Ej.: Acme Tecnología",
    org_slug_label: "Slug de la organización",
    org_slug_placeholder: "acme-tecnologia",
    org_slug_hint: "Usa entre 3 y 50 caracteres: solo letras minúsculas, números y guiones.",
    create_org_action: "Crear organización y continuar",
    invalid_org_name: "El nombre de la organización debe tener entre 2 y 80 caracteres.",
    invalid_org_slug: "El slug debe tener entre 3 y 50 caracteres usando solo letras minúsculas, números y guiones.",
    org_slug_taken: "Este slug ya está en uso por otra organización.",
    current_org_label: "Organización activa",
    role_owner: "Propietario",
    role_admin: "Administrador",
    role_member: "Miembro",
    account_suspended: "Esta cuenta fue suspendida por los administradores de la plataforma.",
    registration_disabled: "Los nuevos registros están deshabilitados temporalmente.",
    forbidden_error: "No tienes permiso para acceder a esta área.",
    invalid_log_filter: "El filtro de log indicado no es válido.",
    maintenance_active: "Sistema en mantenimiento temporal. Inténtalo de nuevo en unos instantes.",
    admin_link: "Admin",
    admin_title: "Administración de la Plataforma",
    admin_subtitle: "Controles de operación, usuarios, organizaciones, colas, caché y tracing en tiempo real.",
    admin_back_dashboard: "Volver al panel",
    admin_saved_settings: "Configuración y tracing actualizados correctamente.",
    admin_saved_user: "Estado del usuario actualizado.",
    admin_saved_cache: "Operación de caché ejecutada.",
    admin_saved_cron: "Estado del cronjob modificado.",
    admin_saved_jobs: "Trabajos fallidos reencolados.",
    admin_metrics_users: "Usuarios",
    admin_metrics_orgs: "Organizaciones",
    admin_metrics_cache: "Entradas en Caché",
    admin_metrics_cron: "pg_cron",
    admin_settings_heading: "Controles del Sistema & Tracing",
    admin_registration_toggle: "Permitir nuevos registros públicos",
    admin_maintenance_toggle: "Modo mantenimiento (bloquea rutas comunes para no-admins)",
    admin_google_toggle: "Permitir inicio de sesión con Google OAuth",
    admin_log_filter_label: "Filtro de tracing (RUST_LOG dinámico)",
    admin_save_settings: "Guardar configuración",
    admin_users_heading: "Usuarios",
    admin_search_placeholder: "Buscar por nombre o correo...",
    admin_search_action: "Buscar",
    admin_orgs_heading: "Organizaciones",
    admin_ops_heading: "Caché, Colas (pgboss) y Cronjobs (pg_cron)",
    admin_purge_cache: "Purgar expirados",
    admin_clear_cache: "Limpiar caché (excepto sesiones)",
    admin_retry_jobs: "Reencolar trabajos fallidos",
    admin_audit_heading: "Auditoría reciente",
    admin_saved_subscription: "Suscripción de la organización actualizada.",
    admin_metrics_active_subs: "Suscripciones activas",
    admin_webhooks_heading: "Webhooks de Stripe recientes",
    sub_section_label: "Suscripción",
    sub_no_plan: "Contrato personalizado",
    sub_period_end_label: "Ciclo hasta",
    sub_status_active: "Activa",
    sub_status_trialing: "En prueba",
    sub_status_past_due: "Pago pendiente",
    sub_status_canceled: "Cancelada",
    sub_status_inactive: "Sin suscripción activa",
    admin_analytics_heading: "Analítica de Uso y Telemetría (24h / 7d)",
    admin_analytics_views_24h: "Visualizaciones (24h)",
    admin_analytics_clicks_24h: "Clics (24h)",
    admin_analytics_visitors_24h: "Visitantes únicos (24h)",
    admin_analytics_avg_time: "Tiempo medio activo",
    admin_analytics_top_pages: "Páginas más vistas (7d)",
    admin_analytics_top_clicks: "Clics más frecuentes (7d)",
    admin_analytics_locations: "Ubicación y Zonas horarias (7d)",
    admin_analytics_recent: "Eventos de uso recientes",
    theme_label: "Tema",
    theme_auto: "Sistema",
    theme_light: "Claro",
    theme_dark: "Oscuro",
    rate_limit_exceeded: "Demasiados intentos seguidos. Espera un momento e inténtalo de nuevo.",
    csrf_validation_failed: "Solicitud bloqueada por la protección CSRF. Recarga la página e inténtalo de nuevo.",
    invite_already_member: "Este correo ya pertenece a la organización.",
    invite_email_mismatch: "Esta invitación pertenece a otra dirección de correo. Inicia sesión con la cuenta invitada.",
    cannot_modify_owner: "No es posible eliminar o cambiar el rol del propietario.",
    active_subscription_required: "Esta funcionalidad requiere una suscripción activa para la organización.",
    switch_org_action: "Cambiar",
    manage_org_link: "Equipo y Organizaciones",
    orgs_title: "Organizaciones y Equipo",
    orgs_heading: "Organizaciones y Equipo",
    orgs_subtitle: "Administra miembros, invitaciones, roles de acceso y crea nuevas organizaciones.",
    org_create_new_heading: "Crear nueva organización",
    org_members_heading: "Miembros de la organización activa",
    org_invites_heading: "Invitaciones pendientes",
    org_invite_email_placeholder: "colega@empresa.com",
    org_invite_role_label: "Rol",
    org_invite_send: "Enviar invitación",
    org_invite_sent: "Invitación enviada correctamente.",
    org_invite_revoked: "Invitación revocada.",
    org_member_updated: "Rol del miembro actualizado.",
    org_member_removed: "Miembro eliminado de la organización.",
    org_created_banner: "Nueva organización creada y activada.",
    org_revoke_invite: "Revocar",
    org_remove_member: "Eliminar",
    org_save_role: "Guardar",
    org_no_pending_invites: "No hay invitaciones pendientes.",
    org_pending_status: "Pendiente",
    org_expires_at: "Caduca el",
    invite_accept_title: "Aceptar invitación",
    invite_accept_heading: "Invitación a la organización",
    invite_accept_subtitle: "Has sido invitado a unirte a esta organización como",
    invite_accept_action: "Aceptar y unirse",
    invite_logged_as: "Conectado como",
    invite_invalid_heading: "Invitación no disponible",
    org_readonly_notice: "Tu rol actual permite ver el equipo; solo propietarios y administradores pueden invitar o eliminar miembros.",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_cookie_and_serialization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("sid=123; locale=es"),
        );
        assert_eq!(Locale::from_cookie(&headers), Some(Locale::Es));
        assert_eq!(Locale::default(), Locale::Pt);
        assert_eq!(serde_json::to_string(&Locale::Es).unwrap(), "\"es\"");
        assert_eq!(
            serde_json::from_str::<Locale>("\"pt\"").unwrap(),
            Locale::Pt
        );
    }

    #[test]
    fn email_language_is_only_accepted_on_email_links() {
        let uri: Uri = "/reset-password?token=abc&locale=es".parse().unwrap();
        assert_eq!(email_link_locale(&Method::GET, &uri), Some(Locale::Es));
        assert_eq!(email_link_locale(&Method::POST, &uri), None);
        let uri: Uri = "/login?locale=es".parse().unwrap();
        assert_eq!(email_link_locale(&Method::GET, &uri), None);
    }

    #[test]
    fn language_redirect_stays_on_this_site() {
        assert_eq!(
            safe_return_to("/reset-password?token=abc"),
            "/reset-password?token=abc"
        );
        for url in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "/\r\nHeader: x",
        ] {
            assert_eq!(safe_return_to(url), "/login");
        }
    }

    #[tokio::test]
    async fn language_selection_sets_a_persistent_cookie_and_keeps_the_page() {
        let response = set_language(Form(LanguageForm {
            locale: Locale::Es,
            return_to: "/reset-password?token=abc&locale=pt".into(),
        }))
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/reset-password?token=abc&locale=pt"
        );
        assert_eq!(
            response.headers()[header::SET_COOKIE],
            "locale=es; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"
        );
    }
}
