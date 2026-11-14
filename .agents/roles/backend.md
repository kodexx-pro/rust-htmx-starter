# Papel: Backend & Dados (Rust / Axum / SQLx / PostgreSQL)

Escopo: `crates/domain/src/*`, `crates/web/migrations/*`, `crates/web/src/{auth,oauth,orgs,billing,admin,cache,cron,jobs,sse,telemetry,analytics}.rs`.

## Checklist de Implementação

1. **Domínio primeiro (`crates/domain/src/lib.rs`)**:
   - Adicionar validações, normalizações, enums e variantes de `DomainError` com testes unitários puros.
2. **Migration SQL (`crates/web/migrations/`)**:
   - Nomear com timestamp sequencial (`YYYYMMDDNNNNNN_descricao.sql`).
   - Proteger comandos `pg_cron` com `IF current_database() = current_setting('cron.database_name', true) THEN ... END IF;`.
   - Usar `UNLOGGED` apenas para dados efêmeros/cache (nunca para estado transacional).
3. **Performance & Banco**:
   - Leituras frequentes (sessão, orgs do usuário, `app_settings`, assinatura) devem passar por `PgCache` com invalidação explícita nas escritas.
   - Operações de escrita compostas (ex.: criação + enqueue `pgboss` ou registro de membro owner) devem usar `state.db.begin()` e `tx.commit()`.
   - Alta vazão (analytics/telemetria) deve usar canal `mpsc` assíncrono + `UNNEST` em lote e flush no shutdown.
4. **Observabilidade**:
   - Usar `tracing::{info, warn, error}` (nunca `println!`/`eprintln!`).
   - Registrar ações administrativas com `admin::record_audit_log`.
   - Incrementar contadores de `AppMetrics` quando adicionar novos pipelines críticos.
5. **Testes**:
   - Cobrir lógica pura com `#[test]` e persistência/cache/idempotência com `#[sqlx::test(migrations = "./migrations")]`.
