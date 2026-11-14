# Workflow: Entrega de Feature End-to-End

1. **Escopo & Contrato**:
   - Definir rota(s), modelo de dados (`domain` + `migration`), chaves de cache (`PgCache`), eventos (`analytics`/`tracing`) e textos (`pt`/`es`).
2. **Camada Base (sequencial ou dono único)**:
   - Atualizar `crates/domain/src/lib.rs` e criar migration em `crates/web/migrations/`.
3. **Implementação Paralela (sem conflito de arquivo)**:
   - **Agente Backend**: novo módulo `crates/web/src/<modulo>.rs` + testes unitários e `#[sqlx::test]`.
   - **Agente Frontend**: templates Askama em `crates/web/templates/` + `data-track` / HTMX.
4. **Integração (dono único)**:
   - Conectar módulo e rotas em `crates/web/src/main.rs`.
   - Mapear erros/traduções em `crates/web/src/error.rs` e `crates/web/src/i18n.rs`.
   - Integrar métricas/controles em `crates/web/src/admin.rs` e `crates/web/templates/admin.html`, se aplicável.
   - Atualizar `.env.example` e `README.md`.
5. **Validação Final**:
   - Subir PostgreSQL (`docker compose up -d`).
   - Rodar `cargo test --workspace -- --include-ignored`.
   - Subir `web` em contêiner, validar fluxo completo no navegador (Chromium) + endpoints HTTP (`/healthz`, `/metrics`, logs `tracing`) e encerrar contêineres temporários ao concluir.
