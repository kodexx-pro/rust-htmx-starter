use askama::Template;
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use domain::DomainError;
use thiserror::Error;

use crate::i18n::{Locale, Translations};

#[derive(Template)]
#[template(path = "partials/flash_alert.html")]
pub struct FlashAlertTemplate {
    pub kind: &'static str,
    pub message: String,
}

pub struct HtmlTemplate<T>(pub T);

impl<T: Template> IntoResponse for HtmlTemplate<T> {
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => AppError::Unexpected(err.into()).into_response(),
        }
    }
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error(transparent)]
    Domain(#[from] DomainError),

    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(Clone, Copy)]
enum ErrorKind {
    InvalidCredentials,
    EmailAlreadyInUse,
    InvalidEmail,
    InvalidName,
    WeakPassword,
    InvalidOrExpiredToken,
    InvalidOrganizationName,
    InvalidOrganizationSlug,
    OrganizationSlugTaken,
    AccountSuspended,
    RegistrationDisabled,
    Forbidden,
    InvalidLogFilter,
    RateLimitExceeded,
    CsrfValidationFailed,
    InviteAlreadyMember,
    InviteEmailMismatch,
    CannotModifyOwner,
    ActiveSubscriptionRequired,
    Unexpected,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    RequestError,
}

impl ErrorKind {
    fn message(self, t: &Translations) -> &'static str {
        match self {
            Self::InvalidCredentials => t.invalid_credentials,
            Self::EmailAlreadyInUse => t.email_in_use,
            Self::InvalidEmail => t.invalid_email,
            Self::InvalidName => t.invalid_name,
            Self::WeakPassword => t.weak_password,
            Self::InvalidOrExpiredToken => t.invalid_token,
            Self::InvalidOrganizationName => t.invalid_org_name,
            Self::InvalidOrganizationSlug => t.invalid_org_slug,
            Self::OrganizationSlugTaken => t.org_slug_taken,
            Self::AccountSuspended => t.account_suspended,
            Self::RegistrationDisabled => t.registration_disabled,
            Self::Forbidden => t.forbidden_error,
            Self::InvalidLogFilter => t.invalid_log_filter,
            Self::RateLimitExceeded => t.rate_limit_exceeded,
            Self::CsrfValidationFailed => t.csrf_validation_failed,
            Self::InviteAlreadyMember => t.invite_already_member,
            Self::InviteEmailMismatch => t.invite_email_mismatch,
            Self::CannotModifyOwner => t.cannot_modify_owner,
            Self::ActiveSubscriptionRequired => t.active_subscription_required,
            Self::Unexpected => t.internal_error,
            Self::BadRequest => t.bad_request,
            Self::NotFound => t.not_found,
            Self::MethodNotAllowed => t.method_not_allowed,
            Self::RequestError => t.request_error,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, kind) = match self {
            AppError::Domain(err) => match err {
                DomainError::InvalidCredentials => {
                    (StatusCode::UNAUTHORIZED, ErrorKind::InvalidCredentials)
                }
                DomainError::EmailAlreadyInUse => {
                    (StatusCode::CONFLICT, ErrorKind::EmailAlreadyInUse)
                }
                DomainError::InvalidEmail => {
                    (StatusCode::UNPROCESSABLE_ENTITY, ErrorKind::InvalidEmail)
                }
                DomainError::InvalidName => {
                    (StatusCode::UNPROCESSABLE_ENTITY, ErrorKind::InvalidName)
                }
                DomainError::WeakPassword => {
                    (StatusCode::UNPROCESSABLE_ENTITY, ErrorKind::WeakPassword)
                }
                DomainError::InvalidOrExpiredToken => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorKind::InvalidOrExpiredToken,
                ),
                DomainError::InvalidOrganizationName => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorKind::InvalidOrganizationName,
                ),
                DomainError::InvalidOrganizationSlug => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorKind::InvalidOrganizationSlug,
                ),
                DomainError::OrganizationSlugTaken => {
                    (StatusCode::CONFLICT, ErrorKind::OrganizationSlugTaken)
                }
                DomainError::AccountSuspended => {
                    (StatusCode::FORBIDDEN, ErrorKind::AccountSuspended)
                }
                DomainError::RegistrationDisabled => {
                    (StatusCode::FORBIDDEN, ErrorKind::RegistrationDisabled)
                }
                DomainError::Forbidden => (StatusCode::FORBIDDEN, ErrorKind::Forbidden),
                DomainError::InvalidLogFilter => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorKind::InvalidLogFilter,
                ),
                DomainError::RateLimitExceeded => {
                    (StatusCode::TOO_MANY_REQUESTS, ErrorKind::RateLimitExceeded)
                }
                DomainError::CsrfValidationFailed => {
                    (StatusCode::FORBIDDEN, ErrorKind::CsrfValidationFailed)
                }
                DomainError::InviteAlreadyMember => {
                    (StatusCode::CONFLICT, ErrorKind::InviteAlreadyMember)
                }
                DomainError::InviteEmailMismatch => {
                    (StatusCode::FORBIDDEN, ErrorKind::InviteEmailMismatch)
                }
                DomainError::CannotModifyOwner => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorKind::CannotModifyOwner,
                ),
                DomainError::ActiveSubscriptionRequired => (
                    StatusCode::PAYMENT_REQUIRED,
                    ErrorKind::ActiveSubscriptionRequired,
                ),
            },
            AppError::Unexpected(err) => {
                tracing::error!(error = ?err, "Erro interno não tratado");
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorKind::Unexpected)
            }
        };

        // The locale middleware renders this marker after the handler completes.
        let mut response = status.into_response();
        response.extensions_mut().insert(kind);
        response
    }
}

pub fn localize_response(
    mut response: Response,
    locale: Locale,
    error_target: &'static str,
) -> Response {
    let kind = response.extensions_mut().remove::<ErrorKind>().or_else(|| {
        if response.headers().contains_key("HX-Redirect") {
            return None;
        }
        match response.status() {
            StatusCode::BAD_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::UNSUPPORTED_MEDIA_TYPE => Some(ErrorKind::BadRequest),
            StatusCode::NOT_FOUND => Some(ErrorKind::NotFound),
            StatusCode::METHOD_NOT_ALLOWED => Some(ErrorKind::MethodNotAllowed),
            status if status.is_client_error() => Some(ErrorKind::RequestError),
            status if status.is_server_error() => Some(ErrorKind::Unexpected),
            _ => None,
        }
    });

    if let Some(kind) = kind {
        let t = locale.translations();
        let html = FlashAlertTemplate {
            kind: "alert-error",
            message: kind.message(t).to_string(),
        }
        .render()
        .unwrap_or_else(|_| {
            format!(
                r#"<div role="alert" class="alert alert-error">{}</div>"#,
                t.critical_error
            )
        });

        *response.body_mut() = Body::from(html);
        let headers = response.headers_mut();
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert("hx-retarget", HeaderValue::from_static(error_target));
        headers.insert("hx-reswap", HeaderValue::from_static("innerHTML"));
    }
    response.headers_mut().insert(
        header::CONTENT_LANGUAGE,
        HeaderValue::from_static(locale.html_lang()),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn domain_errors_keep_their_status_and_are_translated() {
        let cases = [
            (
                DomainError::InvalidCredentials,
                StatusCode::UNAUTHORIZED,
                "Correo electrónico o contraseña incorrectos.",
            ),
            (
                DomainError::EmailAlreadyInUse,
                StatusCode::CONFLICT,
                "Este correo electrónico ya está registrado.",
            ),
            (
                DomainError::InvalidEmail,
                StatusCode::UNPROCESSABLE_ENTITY,
                "Introduce una dirección de correo electrónico válida.",
            ),
            (
                DomainError::InvalidName,
                StatusCode::UNPROCESSABLE_ENTITY,
                "El nombre debe tener al menos 2 caracteres.",
            ),
            (
                DomainError::WeakPassword,
                StatusCode::UNPROCESSABLE_ENTITY,
                "La contraseña debe tener al menos 8 caracteres.",
            ),
            (
                DomainError::InvalidOrExpiredToken,
                StatusCode::UNPROCESSABLE_ENTITY,
                "El enlace de verificación o restablecimiento no es válido o ha caducado.",
            ),
        ];
        for (error, status, expected) in cases {
            let response = localize_response(
                AppError::Domain(error).into_response(),
                Locale::Es,
                "#auth-feedback",
            );
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["HX-Retarget"], "#auth-feedback");
            assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "es");
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(std::str::from_utf8(&body).unwrap().contains(expected));
        }
    }

    #[tokio::test]
    async fn framework_errors_are_translated_without_losing_redirects() {
        let response = localize_response(
            StatusCode::NOT_FOUND.into_response(),
            Locale::Es,
            "#auth-feedback",
        );
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("Página no encontrada.")
        );

        let response = localize_response(
            (StatusCode::UNAUTHORIZED, [("HX-Redirect", "/login")]).into_response(),
            Locale::Es,
            "#auth-feedback",
        );
        assert_eq!(response.headers()["HX-Redirect"], "/login");
        assert!(!response.headers().contains_key("HX-Retarget"));
    }
}
