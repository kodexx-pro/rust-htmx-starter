# Rust + Axum + Askama + HTMX + DaisyUI Starter

Monorepo full-stack em Rust que compila frontend, templates HTML, migrations SQL, autenticação com cookies assinados, filas com `pgboss` e envio de e-mails com Resend em um **único binário executável**.

## Stack

- **Backend & HTTP:** Axum 0.8 + Tokio
- **Templates HTML tipados:** Askama (validados em tempo de compilação)
- **Interatividade:** HTMX + DaisyUI (Tailwind CSS standalone CLI, sem Node.js)
- **Banco de Dados & Migrations:** PostgreSQL + SQLx (`sqlx::migrate!`)
- **Autenticação:** Sessões em banco + `SignedCookieJar` (`axum-extra`) + Argon2 (`password-auth`)
- **Filas em Background:** Crate `pgboss` (PostgreSQL-backed job queue)
- **E-mails Transacionais:** API do Resend (`reqwest`)

## Como rodar localmente

### 1. Suba o PostgreSQL

```bash
docker compose up -d
```

### 2. Configure as variáveis de ambiente

```bash
cp .env.example .env
# Carregue as variáveis no shell (ou use direnv / dotenv)
export $(grep -v '^#' .env | xargs)
```

### 3. (Opcional) Compile o CSS completo do Tailwind + DaisyUI sem Node.js

O arquivo `crates/web/assets/app.css` já vem com estilos básicos para compilar de imediato. Para gerar o pacote completo do DaisyUI:

```bash
# Baixe o Tailwind standalone CLI e os arquivos do DaisyUI
curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
chmod +x tailwindcss-linux-x64
curl -sLo crates/web/assets/daisyui.mjs https://github.com/saadeghi/daisyui/releases/latest/download/daisyui.mjs
curl -sLo crates/web/assets/daisyui-theme.mjs https://github.com/saadeghi/daisyui/releases/latest/download/daisyui-theme.mjs

# Compile e minifique o CSS
./tailwindcss-linux-x64 -i crates/web/assets/input.css -o crates/web/assets/app.css --minify
```

Baixe também o `htmx.min.js` oficial (opcional, caso queira atualizar o asset local):

```bash
curl -sLo crates/web/assets/htmx.min.js https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js
```

### 4. Execute a aplicação

```bash
cargo run -p web
```

Acesse `http://localhost:3000` para a página pública. A área autenticada fica em `/dashboard`.

## Idiomas

A interface e os e-mails estão disponíveis em português e espanhol. O seletor salva a preferência em um cookie; sem preferência, a aplicação usa português. Links enviados por e-mail levam o idioma do job e o aplicam caso ainda não exista preferência. Jobs antigos sem idioma usam português.

Para adicionar outro idioma, atualize `crates/web/src/i18n.rs` e os textos dos e-mails em `crates/web/src/jobs.rs`.

## Filas de e-mail

A aplicação usa a crate Rust `pgboss` 0.1.0-rc5, uma implementação compatível com pg-boss, não a biblioteca oficial de Node.js. Na inicialização, ela cria o schema e as filas `email.verify` e `email.reset_password`, reutilizando o pool SQLx da aplicação. O usuário do banco precisa ter permissão para criar o schema e seus objetos.

Cada instância executa um consumidor por fila, consultando o banco a cada segundo quando não há jobs. Falhas de processamento recebem até três novas tentativas, com intervalo de 30 segundos. A manutenção de jobs ativos expirados é executada a cada minuto. A entrega é pelo menos uma vez: uma interrupção após o envio do e-mail e antes da confirmação pode causar envio duplicado.

Nesta versão da crate, `force_maintain` recupera jobs expirados, mas não remove jobs concluídos ou antigos. Planeje a limpeza e monitore o crescimento das tabelas. Os payloads incluem links com tokens e devem ser protegidos como dados sensíveis.

O cadastro grava usuário, sessão, token e job de verificação na mesma transação PostgreSQL. Se a inserção do job falhar, o cadastro é revertido. A inserção transacional reproduz o SQL da crate para o schema padrão `pgboss`; ao atualizar a versão da crate ou alterar o schema, revise a compatibilidade.

## Eventos em tempo real (SSE)

A aplicação expõe `GET /events` (`crates/web/src/sse.rs`) usando `axum::response::sse::Sse` autenticado por `AuthenticatedSession` e `EventBus` (`tokio::sync::broadcast`) em `AppState`:

- `email-verified`: ao confirmar o e-mail em `GET /verify-email`, abas abertas em `/dashboard` atualizam `#verification-badge`, limpam `#verification-banner` e exibem o toast localizado sem recarregar a página.
- `session-revoked`: ao encerrar a sessão em `POST /logout` ou redefinir a senha em `POST /reset-password`, o stream envia o evento, encerra a conexão e redireciona abas abertas para `/login`.

A aplicação usa um único `sqlx::postgres::PgListener` dedicado (`LISTEN app_realtime_events`) alimentando o `EventBus` via `pg_notify`, sincronizando eventos em tempo real entre múltiplas réplicas sem reter conexões do `PgPool` por cliente SSE.

## Login com Google (OIDC)

A autenticação utiliza a crate `openidconnect` (Authorization Code + PKCE + validação de ID Token e `nonce`), permitindo que o usuário escolha entrar com **Google** ou **e-mail e senha** em `/login` e `/register`.

- Configure `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET` (opcionais; sem eles a aplicação inicia normalmente e exibe aviso ao clicar no botão).
- No Google Cloud Console, cadastre a URI de redirecionamento `${APP_URL}/auth/google/callback` (por padrão `http://localhost:3000/auth/google/callback`).
- Usuários autenticados via Google são gravados em `oauth_accounts` com `password_hash` nulo em `users` e `email_verified = TRUE` quando o Google confirmar o e-mail; contas existentes com o mesmo e-mail são vinculadas automaticamente se o e-mail retornado pelo Google estiver verificado.

## Cache em PostgreSQL (`UNLOGGED` + Stored Procedures)

Em vez de Redis, o projeto utiliza a tabela `UNLOGGED` `cache_entries` (`payload TEXT` com JSON e `expires_at TIMESTAMPTZ`) controlada pelas stored procedures/funções `cache_set`, `cache_get`, `cache_ttl`, `cache_del`, `cache_del_prefix` e `cache_purge_expired`.

- `PgCache` (`crates/web/src/cache.rs`) expõe `get`, `set`, `get_or_set`, `delete`, `delete_prefix`, `ttl` e `purge_expired`.
- Entradas expiradas são removidas de forma *lazy* em `cache_get`/`cache_ttl` e em lote pelo job `cleanup-expired-cache` do `pg_cron` (`CALL cache_purge_expired()`).
- Já integrado para cache de sessão (`session:<id>`, TTL máximo de 5 min limitado ao `expires_at` da sessão e invalidado em logout/verificação de e-mail/redefinição de senha) e discovery OIDC do Google (`oidc:google:metadata`, TTL de 1 hora).
- Por ser uma tabela `UNLOGGED`, o conteúdo não gera WAL e é truncado automaticamente pelo PostgreSQL em caso de crash recovery, mantendo os dados persistentes íntegros nas tabelas normais.

## Cronjobs (`pg_cron`)

O PostgreSQL do `docker-compose.yml` usa `Dockerfile.postgres` (`postgres:17` + `postgresql-17-cron`) com `shared_preload_libraries=pg_cron` e `cron.database_name=app_starter`.

- A migration `crates/web/migrations/20261113000004_cron_jobs.sql` habilita `pg_cron` (quando conectada ao banco definido em `cron.database_name`) e agenda 4 tarefas recorrentes:
  - `cleanup-expired-cache` (`* * * * *`): `CALL cache_purge_expired()` (limpeza em lote executada diretamente pelo PostgreSQL).
  - `cleanup-expired-sessions` (`*/15 * * * *`): remove sessões expiradas de `sessions`.
  - `cleanup-expired-auth-tokens` (`0 3 * * *`): remove tokens expirados ou usados antigos de `auth_tokens`.
  - `cleanup-cron-history` (`0 4 * * *`): retém os últimos 7 dias em `cron.job_run_details`.
- `PgCron` (`crates/web/src/cron.rs`, disponível no `AppState`) expõe `is_enabled`, `schedule`, `schedule_in_database`, `unschedule`, `set_active`, `job_by_name`, `list_jobs` e `recent_runs`.

## Organizações e Onboarding

- Tabelas `organizations` (`id`, `name`, `slug` único em minúsculas, `created_by`, timestamps) e `organization_members` (`organization_id`, `user_id`, `role` em `owner` | `admin` | `member`) criadas em `crates/web/migrations/20261113000005_organizations.sql`.
- Pós-autenticação obrigatório: após cadastro (`POST /register`), login por senha (`POST /login`), callback OIDC do Google (`GET /auth/google/callback`) ou verificação de e-mail (`GET /verify-email`), usuários sem organização são direcionados automaticamente para `GET /onboarding` (e `GET /dashboard` redireciona para `/onboarding` enquanto não houver organização vinculada).
- Em `GET/POST /onboarding` (`crates/web/src/orgs.rs`), o usuário cria sua primeira organização informando `name` e `slug` (validados no `domain` e com pré-preenchimento automático no cliente), recebendo o papel `owner` e invalidando o cache `user_orgs:<user_id>`.

## Observabilidade (`tracing`) e Painel `/admin`

- `crates/web/src/telemetry.rs` inicializa `tracing-subscriber` com `RUST_LOG` (padrão `web=info,tower_http=info,sqlx=warn`), `LOG_FORMAT` (`compact` ou `json`), `x-request-id` propagado por requisição via `tower-http`, `TraceLayer` HTTP, endpoint `GET /healthz` e `graceful shutdown`.
- `crates/web/migrations/20261113000006_admin.sql` adiciona `users.is_platform_admin`, `users.suspended_at`, `app_settings` (singleton cacheado no `PgCache`) e `audit_logs`.
- Defina `ADMIN_EMAILS=voce@empresa.com` no `.env` para promover administradores automaticamente no boot ou no cadastro/login.
- O painel `GET /admin` (protegido pelo extrator `PlatformAdmin`, que exige `is_platform_admin = TRUE` e retorna `403` para demais usuários) permite:
  - Alternar em tempo real `registration_enabled`, `google_oauth_enabled`, `maintenance_mode` e o filtro de `tracing` (`RUST_LOG` dinâmico sem reiniciar);
  - Buscar usuários, conceder/revogar acesso admin e suspender/reativar contas (revogando sessões via banco, cache e SSE);
  - Inspecionar organizações, limpar cache (`UNLOGGED`), reenfileirar jobs falhos do `pgboss`, pausar/reativar jobs do `pg_cron` e consultar `audit_logs`.

## Assinaturas por Organização & Webhook Stripe

Como o modelo comercial parte de vendas por negociação (sem tabela fixa de preços no código), o projeto controla o ciclo de vida das assinaturas apenas por organização e webhook:

- Migration `crates/web/migrations/20261113000007_stripe_subscriptions.sql`:
  - `organization_subscriptions`: armazena `status`, `plan_name` (rótulo livre do contrato negociado), `stripe_customer_id`, `stripe_subscription_id`, janela do ciclo (`current_period_start`/`current_period_end`) e `metadata` JSONB por `organization_id`;
  - `stripe_webhook_events`: garante idempotência (`stripe_event_id` PK) e trilha de processamento (`processed` / `ignored` / `failed`).
- Endpoint `POST /webhooks/stripe` (`crates/web/src/billing.rs`):
  - Valida `Stripe-Signature` (`HMAC-SHA256` em tempo constante + janela de 300s usando `STRIPE_WEBHOOK_SECRET`, opcional no boot);
  - Resolve a organização via `metadata.organization_id`, `client_reference_id`, `stripe_subscription_id` ou `stripe_customer_id` para eventos `customer.subscription.*`, `checkout.session.completed`, `invoice.paid`/`invoice.payment_succeeded` e `invoice.payment_failed`;
  - Invalida o cache `org_sub:<organization_id>` no `PgCache` após cada atualização.
- O painel `/admin` permite vincular manualmente `stripe_customer_id`, `stripe_subscription_id`, `status` e `plan_name` por organização para contratos negociados e inspecionar os webhooks recebidos, enquanto `/dashboard` exibe o estado atual da assinatura da organização ativa.

## Analytics de Uso, Métricas (`/metrics`) & Tracing

- Migration `crates/web/migrations/20261113000008_analytics.sql`:
  - Tabela `analytics_events` para `page_view`, `click`, `page_leave` (tempo ativo em ms) e eventos `custom`, com índices para usuário, organização, rota e janela temporal, além de job `cleanup-old-analytics` no `pg_cron` (retenção de 90 dias).
- Coleta em lote não-bloqueante (`crates/web/src/analytics.rs` + rastreador em `crates/web/templates/base.html`):
  - Frontend agrupa cliques (com alvo, rótulo sanitizado e coordenadas `%`), visualizações de página/HTMX, seções visíveis (`data-track-view`), tempo ativo (`visibilitychange` + `pagehide` via `sendBeacon`), fuso horário e viewport, além da API `window.appTrack(name, props)`.
  - Backend resolve `visitor_id` (cookie assinado `vid`), `user_id` + `organization_id` da sessão autenticada, geolocalização via headers de proxy/CDN (`cf-ipcountry`, `x-vercel-ip-*`, `cloudfront-viewer-*`, `fly-*`), tipo de dispositivo e `ip_hash` pseudonimizado (`HMAC-SHA256`), emitindo eventos estruturados no `tracing` (`target = "web::analytics"`) e persistindo via canal `mpsc` + `UNNEST` em lote.
- Métricas Prometheus em `GET /metrics` (`crates/web/src/telemetry.rs`, protegido opcionalmente por `METRICS_TOKEN`) e painel consolidado em `/admin`.

## Multi-tenant (`OrgContext`), RBAC e Convites

- `OrgContext` (`crates/web/src/orgs.rs`) resolve a organização ativa a partir do cookie assinado `org_id` (`ACTIVE_ORG_COOKIE`), valida o vínculo em `organization_members` e carrega a assinatura em `PgCache`, expondo `require_admin()`, `require_owner()` e `require_active_subscription()`.
- Em `/dashboard` e `/organizations`, usuários podem alternar entre organizações (`POST /organizations/switch`), criar novas organizações (`POST /organizations`), gerenciar papéis (`owner`/`admin`/`member`) e enviar convites por e-mail (`POST /organizations/invites`, gravando `token_hash` SHA-256 em `organization_invites` e enfileirando `email.org_invite` no `pgboss` na mesma transação).
- Convites são aceitos em `/invites/accept?token=...` (preservando `?next=` caso o usuário precise autenticar ou cadastrar-se antes).

## Segurança: Rate Limiting (`PgCache`) e CSRF

- **Rate limiting atômico (`crates/web/src/security.rs`)**: função SQL `cache_incr` em `cache_entries` (`UNLOGGED`) aplica janela fixa por IP pseudonimizado (`HMAC-SHA256`) em `/login`, `/register`, `/forgot-password`, `/resend-verification`, `/reset-password`, `/organizations/invites` e `/analytics/collect`, retornando `429` com `Retry-After`.
- **Proteção CSRF**: valida `Sec-Fetch-Site` (`same-origin`/`none`) e `Origin`/`Referer` contra `APP_URL`/`Host` em todos os métodos de escrita (`POST`/`PUT`/`PATCH`/`DELETE`), isentando apenas `/webhooks/*`.

## Build de Produção (`Dockerfile`) e CI

- `Dockerfile` multi-stage usa `cargo-chef` para cache de dependências Rust, gera `app.css` minificado com Tailwind CLI + DaisyUI 5 e embute `htmx.min.js` v2.0.4 **100% offline** dentro do binário em imagem final `debian:bookworm-slim` com usuário não-root e `HEALTHCHECK` em `/healthz`.
- Suba toda a stack compilada com `docker compose --profile app up -d --build`.
- `.github/workflows/ci.yml` executa `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` e `cargo test --workspace -- --include-ignored` contra PostgreSQL 17 + `pg_cron`.
