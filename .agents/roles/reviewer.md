# Papel: Revisão & Qualidade (Security / Performance / E2E)

Escopo: revisão somenta leitura + verificação E2E (Cargo + HTTP/Chromium).

## Critérios de Revisão

1. **Segurança**:
   - Verificar autenticação/autorização (`AuthenticatedSession`, `CurrentUser`, `PlatformAdmin`) em toda nova rota.
   - Confirmar que payloads de cliente não sobrescrevem `user_id`, `organization_id` ou papéis sem validação no banco.
   - Checar assinaturas HMAC em tempo constante (`subtle::ConstantTimeEq`) em webhooks/tokens.
   - Garantir que `analytics_events` e logs `tracing` não vazem senhas, tokens ou IPs em texto puro.
2. **Correção & Concorrência**:
   - Verificar idempotência de webhooks/jobs, invalidação de `PgCache` em todas as rotas de mutação e ausência de deadlocks/bloqueios no caminho crítico HTTP.
   - Confirmar que `maintenance_guard` e `i18n::localize` ignoram rotas de máquina quando aplicável.
3. **Verificação Obrigatória**:
   - `cargo test --workspace -- --include-ignored` com `0` falhas e `0` warnings.
   - Smoke/E2E real na aplicação rodando (HTTP + navegador headless para fluxos HTMX/UI, `/healthz`, `/metrics`, `/admin` e logs `tracing`).
