# AGENTS.md — Guia de Trabalho para Agentes

Workspace Rust full-stack (`Axum 0.8 + Askama + HTMX 2.0.4 + DaisyUI 5 + SQLx/PostgreSQL 17 + pgboss + pg_cron + Resend + OpenID Connect + Stripe Webhooks + Tracing/Prometheus/Analytics`).

## 1. Mapa do Workspace

- `crates/domain/`: regras puras de domínio, validações (`email`, `name`, `password`, `organization`), enums (`OrganizationRole`, `SubscriptionStatus`) e `DomainError`. **Sem dependências de HTTP, SQLx ou runtime Tokio.**
- `crates/web/`: aplicação web e workers:
  - `src/main.rs`: bootstrap do pool, migrations, `pgboss`, `PgCache`, `PgCron`, `AnalyticsCollector`, `AppState`, `Router` e graceful shutdown.
  - `src/auth.rs`: sessão via cookie assinado (`sid`, HMAC-SHA512), cache `session:<id>`, login/cadastro, verificação de e-mail e `/dashboard`.
  - `src/oauth.rs`: Google OIDC opcional (PKCE `S256`, `Nonce`, `AccessTokenHash`, metadados em `PgCache`).
  - `src/orgs.rs`: organizações, `OrgContext` (cookie assinado `org_id`, RBAC e checagem de assinatura ativa), troca de org (`POST /organizations/switch`), convites transacionais via `pgboss` (`/organizations`, `/invites/accept`), `/onboarding` e cache `user_orgs:<user_id>`.
  - `src/security.rs`: proteção CSRF (Fetch Metadata `Sec-Fetch-Site` + validação de `Origin`/`Referer` com bypass apenas em `/webhooks/*`) e rate limiting atômico via `cache_incr` na tabela `UNLOGGED` `cache_entries`.
  - `src/billing.rs`: assinaturas por organização (contratos negociados sem planos fixos), webhook `POST /webhooks/stripe` (HMAC-SHA256 + idempotência) e cache `org_sub:<org_id>`.
  - `src/admin.rs`: painel `/admin` (`PlatformAdmin`), `ADMIN_EMAILS`, `app_settings` em cache, `maintenance_guard`, `audit_logs`, gestão de usuários/orgs/cache/cron/filas/analytics.
  - `src/cache.rs`: cache PostgreSQL em tabela `UNLOGGED` (`cache_entries`) via procedures/functions com `clock_timestamp()` (inclui `cache_incr`). **Sem Redis.**
  - `src/cron.rs`: wrapper de `pg_cron` (agendamento, pausa, remoção e histórico).
  - `src/jobs.rs` & `src/mailer.rs`: filas `pgboss = "=0.1.0-rc5"` (`email.verify`, `email.reset_password`, `email.org_invite`), enqueue transacional (`enqueue_transactional`) e envio via Resend.
  - `src/sse.rs`: Server-Sent Events (`/events`) com `tokio::sync::broadcast` alimentado por `PgListener` (`LISTEN/NOTIFY` no canal `app_realtime_events`) para escala horizontal.
  - `src/telemetry.rs`: `tracing` dinâmico (`RUST_LOG` reloadable em `/admin`, `LOG_FORMAT=compact|json`), `x-request-id`, `/healthz`, métricas atômicas e `GET /metrics` (Prometheus).
  - `src/analytics.rs`: `POST /analytics/collect`, cookie assinado `vid`, geo por headers CDN + `ip_hash` (`HMAC-SHA256`), batching `mpsc` + `UNNEST` e eventos `web::analytics`.
  - `src/i18n.rs` & `src/error.rs`: bilingue (`pt` padrão / `es` via cookie `locale`) e tradução automática de erros HTMX/HTML.
  - `templates/` & `assets/`: templates Askama e assets estáticos embutidos no binário (`include_str!`).
  - `migrations/`: migrations SQLx sequenciais (`20261113000001_*` em diante).

## 2. Ambiente, Build, Testes e Execução

Se `cargo`/`psql` não estiverem no `PATH` do host, execute via Docker na rede `rust-htmx-starter_default`:

```bash
# 1. Subir PostgreSQL 17 + pg_cron
docker compose up -d

# 2. Rodar toda a suíte (inclui testes #[ignore] de pg_cron)
docker run --rm --network rust-htmx-starter_default -v .:/work -w /work \
  -e DATABASE_URL=postgres://postgres:postgres@postgres:5432/app_starter \
  rust:latest cargo test --workspace -- --include-ignored

# 3. Subir servidor web local para E2E
docker run -d --name rust-htmx-starter-web --network rust-htmx-starter_default -p 3000:3000 \
  -v .:/work -w /work \
  -e DATABASE_URL=postgres://postgres:postgres@postgres:5432/app_starter \
  -e APP_URL=http://localhost:3000 \
  -e APP_SECRET=troque-esta-chave-por-uma-string-aleatoria-com-pelo-menos-64-bytes-em-producao \
  -e RESEND_API_KEY=re_123456789 \
  -e ADMIN_EMAILS=provider@example.com \
  rust:latest cargo run -p web
```

## 3. Invariantes Obrigatórias (Não Quebrar)

1. **Zero warnings**: código final deve compilar e passar `cargo test --workspace -- --include-ignored` sem warnings.
2. **Isolamento de domínio**: `crates/domain` não importa `sqlx`, `axum`, `tokio` ou `reqwest`.
3. **Sem `chrono` no SQLx**: `sqlx` não habilita `chrono`; formate/converta timestamps no SQL (`TO_CHAR`, `::text`, `EXTRACT(EPOCH ...)`).
4. **Migrations compatíveis com `sqlx::test`**: qualquer uso de `pg_cron` (`CREATE EXTENSION`, `cron.schedule`) deve ser protegido por `IF current_database() = current_setting('cron.database_name', true) THEN ... END IF;`.
5. **pgboss pinado (`=0.1.0-rc5`)**: alterações no schema de jobs exigem conferir `enqueue_transactional` em `crates/web/src/jobs.rs`.
6. **Segurança e identidade**: nunca confiar em `user_id` ou `organization_id` enviados pelo cliente; resolver sempre via cookie assinado (`AuthenticatedSession`, `PlatformAdmin`, `try_resolve_session_user`). Nunca logar ou persistir IPs em texto puro nem valores de inputs de senha.
7. **Invalidação de cache (`PgCache`)**: toda mutação em usuário/sessão, organização, `app_settings` ou assinatura deve invalidar a chave correspondente (`session:<id>`, `user_orgs:<id>`, `app_settings`, `org_sub:<org_id>`).
8. **Bilinguismo (`pt` / `es`)**: toda nova string visível ao usuário ou novo `DomainError` deve atualizar `Translations` (`PORTUGUESE` e `SPANISH`) em `crates/web/src/i18n.rs` e `crates/web/src/error.rs`.
9. **Middlewares de infraestrutura**: rotas de máquina (`/webhooks/*`, `/analytics/*`, `/metrics`, `/healthz`) devem fazer bypass de `i18n::localize` e `admin::maintenance_guard`.
10. **HTMX + Askama**: manter `htmx.config.responseHandling` em `base.html` e `window.htmx.process(document.body)` no loader `assets/htmx.min.js`.

## 4. Coordenação Multi-Agentes

- **Papéis especializados**: ver `.agents/roles/` (`backend.md`, `frontend.md`, `reviewer.md`) e `.agents/workflows/feature-delivery.md`.
- **Propriedade de arquivos**:
  - Evitar edição concorrente no mesmo arquivo. Quando houver trabalho paralelo, dividir por camada (`domain` + `migrations` -> módulos de `web/src/` -> `templates/`) e designar **um único integrador** para `crates/web/src/main.rs`, `crates/web/src/i18n.rs`, `crates/web/src/error.rs` e `crates/web/templates/admin.html`.
- **Verificação final única**: subagentes de implementação não rodam builds repetidos durante edições parciais; executar `cargo test --workspace -- --include-ignored` + smoke/E2E uma vez ao concluir a integração.
