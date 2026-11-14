# Papel: Frontend, HTMX, i18n & Analytics

Escopo: `crates/web/templates/**/*.html`, `crates/web/assets/*`, `crates/web/src/i18n.rs`, `crates/web/src/error.rs`.

## Checklist de Implementação

1. **Templates Askama + DaisyUI**:
   - Estender `base.html` para herdar seletor de idioma, validação customizada, `#toast-container` e coletor automático de analytics.
   - Não deixar variáveis/campos não utilizados nos structs de template.
2. **HTMX**:
   - Formulários interativos usam `hx-post` + feedback alvo (`#auth-feedback`, `#onboarding-feedback`, `#admin-feedback`, `#toast-container`).
   - Redirecionamentos após sucesso em `hx-post` devem retornar cabeçalho `HX-Redirect` no handler.
3. **Bilinguismo (`pt` / `es`)**:
   - Toda label, placeholder, mensagem de erro e status deve existir em `Translations`, `PORTUGUESE` e `SPANISH` em `crates/web/src/i18n.rs`.
   - Novos `DomainError` devem ser mapeados em `crates/web/src/error.rs` com status HTTP semântico (`400`, `401`, `403`, `404`, `409`, `422`, `503`).
4. **Analytics no Frontend**:
   - Anotar CTAs importantes com `data-track="nome-estavel"` e blocos principais com `data-track-view="nome-secao"`.
   - Usar `data-no-track` em áreas sensíveis ou onde cliques não devam gerar eventos.
   - Eventos customizados de produto usam `window.appTrack("evento", { ... })`.
