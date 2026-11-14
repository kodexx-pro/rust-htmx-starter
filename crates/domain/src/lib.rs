use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DomainError {
    #[error("E-mail ou senha inválidos.")]
    InvalidCredentials,

    #[error("Este e-mail já está cadastrado.")]
    EmailAlreadyInUse,

    #[error("Informe um endereço de e-mail válido.")]
    InvalidEmail,

    #[error("O nome precisa ter pelo menos 2 caracteres.")]
    InvalidName,

    #[error("A senha deve ter no mínimo 8 caracteres.")]
    WeakPassword,

    #[error("O link de verificação ou redefinição é inválido ou expirou.")]
    InvalidOrExpiredToken,

    #[error("O nome da organização precisa ter entre 2 e 80 caracteres.")]
    InvalidOrganizationName,

    #[error(
        "O slug deve ter entre 3 e 50 caracteres usando apenas letras minúsculas, números e hífens."
    )]
    InvalidOrganizationSlug,

    #[error("Este slug já está em uso por outra organização.")]
    OrganizationSlugTaken,

    #[error("Esta conta foi suspensa pelos administradores da plataforma.")]
    AccountSuspended,

    #[error("Novos cadastros estão temporariamente desabilitados.")]
    RegistrationDisabled,

    #[error("Você não tem permissão para acessar esta área.")]
    Forbidden,

    #[error("O filtro de log informado é inválido.")]
    InvalidLogFilter,

    #[error("Muitas tentativas em sequência. Aguarde um momento e tente novamente.")]
    RateLimitExceeded,

    #[error("Solicitação bloqueada pela proteção CSRF. Recarregue a página e tente novamente.")]
    CsrfValidationFailed,

    #[error("Este e-mail já pertence à organização.")]
    InviteAlreadyMember,

    #[error("O convite foi enviado para outro endereço de e-mail.")]
    InviteEmailMismatch,

    #[error("Não é possível remover ou rebaixar o proprietário da organização.")]
    CannotModifyOwner,

    #[error("Esta funcionalidade requer uma assinatura ativa para a organização.")]
    ActiveSubscriptionRequired,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub is_platform_admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

impl OrganizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            _ => None,
        }
    }

    pub fn is_owner(self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn can_manage_members(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_manage_roles(self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn can_invite_role(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Owner | Self::Admin, Self::Admin | Self::Member)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub role: OrganizationRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubscriptionStatus {
    #[default]
    Inactive,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
    Incomplete,
    IncompleteExpired,
}

impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Trialing => "trialing",
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
            Self::Unpaid => "unpaid",
            Self::Paused => "paused",
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "inactive" => Some(Self::Inactive),
            "trialing" => Some(Self::Trialing),
            "active" => Some(Self::Active),
            "past_due" => Some(Self::PastDue),
            "canceled" => Some(Self::Canceled),
            "unpaid" => Some(Self::Unpaid),
            "paused" => Some(Self::Paused),
            "incomplete" => Some(Self::Incomplete),
            "incomplete_expired" => Some(Self::IncompleteExpired),
            _ => None,
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active | Self::Trialing)
    }
}

pub fn normalize_email(raw: &str) -> Result<String, DomainError> {
    let email = raw.trim().to_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(DomainError::InvalidEmail);
    };
    if local.is_empty() || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.')
    {
        return Err(DomainError::InvalidEmail);
    }
    Ok(email)
}

pub fn validate_name(raw: &str) -> Result<String, DomainError> {
    let name = raw.trim();
    if name.chars().count() < 2 {
        return Err(DomainError::InvalidName);
    }
    Ok(name.to_string())
}

pub fn validate_password(password: &str) -> Result<(), DomainError> {
    if password.chars().count() < 8 {
        return Err(DomainError::WeakPassword);
    }
    Ok(())
}

pub fn validate_organization_name(raw: &str) -> Result<String, DomainError> {
    let name = raw.trim();
    let len = name.chars().count();
    if !(2..=80).contains(&len) {
        return Err(DomainError::InvalidOrganizationName);
    }
    Ok(name.to_string())
}

pub fn normalize_organization_slug(raw: &str) -> Result<String, DomainError> {
    let slug = raw.trim().to_ascii_lowercase();
    if !(3..=50).contains(&slug.len()) {
        return Err(DomainError::InvalidOrganizationSlug);
    }
    let bytes = slug.as_bytes();
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err(DomainError::InvalidOrganizationSlug);
    }
    let mut prev_hyphen = false;
    for &b in bytes {
        let valid_char = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !valid_char || (b == b'-' && prev_hyphen) {
            return Err(DomainError::InvalidOrganizationSlug);
        }
        prev_hyphen = b == b'-';
    }
    Ok(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_email() {
        assert_eq!(
            normalize_email("  Anderson@Exemplo.COM ").unwrap(),
            "anderson@exemplo.com"
        );
        assert_eq!(normalize_email("invalido"), Err(DomainError::InvalidEmail));
    }

    #[test]
    fn validates_password_length() {
        assert!(validate_password("12345678").is_ok());
        assert_eq!(validate_password("1234567"), Err(DomainError::WeakPassword));
    }

    #[test]
    fn validates_organization_name_and_slug() {
        assert_eq!(
            validate_organization_name("  Acme Corp  ").unwrap(),
            "Acme Corp"
        );
        assert_eq!(
            validate_organization_name("A"),
            Err(DomainError::InvalidOrganizationName)
        );
        assert_eq!(
            normalize_organization_slug("  Minha-Org-01 ").unwrap(),
            "minha-org-01"
        );
        assert_eq!(
            normalize_organization_slug("ab"),
            Err(DomainError::InvalidOrganizationSlug)
        );
        assert_eq!(
            normalize_organization_slug("-minha-org"),
            Err(DomainError::InvalidOrganizationSlug)
        );
        assert_eq!(
            normalize_organization_slug("minha--org"),
            Err(DomainError::InvalidOrganizationSlug)
        );
        assert_eq!(
            normalize_organization_slug("minha_org"),
            Err(DomainError::InvalidOrganizationSlug)
        );
    }

    #[test]
    fn parses_subscription_status_and_active_flag() {
        assert!(SubscriptionStatus::Active.is_active());
        assert!(SubscriptionStatus::Trialing.is_active());
        assert!(!SubscriptionStatus::PastDue.is_active());
        assert!(!SubscriptionStatus::Canceled.is_active());
        assert!(!SubscriptionStatus::Inactive.is_active());
        assert_eq!(
            SubscriptionStatus::parse("active"),
            Some(SubscriptionStatus::Active)
        );
        assert_eq!(
            SubscriptionStatus::parse("past_due"),
            Some(SubscriptionStatus::PastDue)
        );
        assert_eq!(SubscriptionStatus::parse("unknown"), None);
    }

    #[test]
    fn checks_organization_role_permissions() {
        assert!(OrganizationRole::Owner.is_owner());
        assert!(OrganizationRole::Owner.can_manage_members());
        assert!(OrganizationRole::Owner.can_manage_roles());
        assert!(OrganizationRole::Owner.can_invite_role(OrganizationRole::Admin));
        assert!(OrganizationRole::Owner.can_invite_role(OrganizationRole::Member));
        assert!(!OrganizationRole::Owner.can_invite_role(OrganizationRole::Owner));

        assert!(!OrganizationRole::Admin.is_owner());
        assert!(OrganizationRole::Admin.can_manage_members());
        assert!(!OrganizationRole::Admin.can_manage_roles());
        assert!(OrganizationRole::Admin.can_invite_role(OrganizationRole::Member));
        assert!(!OrganizationRole::Admin.can_invite_role(OrganizationRole::Owner));

        assert!(!OrganizationRole::Member.can_manage_members());
        assert!(!OrganizationRole::Member.can_manage_roles());
        assert!(!OrganizationRole::Member.can_invite_role(OrganizationRole::Member));
    }
}
