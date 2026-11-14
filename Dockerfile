# syntax=docker/dockerfile:1

FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM node:22-bookworm-slim AS assets
WORKDIR /app
COPY crates/web/assets ./crates/web/assets
COPY crates/web/templates ./crates/web/templates
COPY crates/web/src ./crates/web/src
RUN npm init -y >/dev/null 2>&1 \
    && npm install --no-save @tailwindcss/cli@^4 tailwindcss@^4 daisyui@^5 htmx.org@2.0.4 \
    && sed 's|@plugin "./daisyui.mjs"|@plugin "daisyui"|g' crates/web/assets/input.css > crates/web/assets/input.docker.css \
    && ./node_modules/.bin/tailwindcss -i crates/web/assets/input.docker.css -o crates/web/assets/app.css --minify \
    && cp node_modules/htmx.org/dist/htmx.min.js crates/web/assets/htmx.min.js

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=assets /app/crates/web/assets/app.css ./crates/web/assets/app.css
COPY --from=assets /app/crates/web/assets/htmx.min.js ./crates/web/assets/htmx.min.js
RUN cargo build --release --bin web

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=builder /app/target/release/web /usr/local/bin/web
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/web"]
