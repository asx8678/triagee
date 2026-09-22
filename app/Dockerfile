# Multi-stage image for the Triage Phoenix application.
#
# Build from the repository root (the build context is app/):
#   docker build -f app/Dockerfile -t triage:0.1.0 app/
#
# The build stage is pinned to the same Elixir/OTP pair as .mise.toml and CI.
# SECRET_KEY_BASE, DATABASE_URL and the ADO_* credentials are read at runtime
# (config/runtime.exs), never at build time: the image contains no secrets.

FROM hexpm/elixir:1.20.4-erlang-27.3.4.17-debian-bookworm AS build

ENV MIX_ENV=prod
WORKDIR /app

RUN apt-get update -y \
  && apt-get install -y --no-install-recommends build-essential ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

# Dependencies first for layer caching; only production dependencies are fetched.
COPY mix.exs mix.lock ./
RUN mix deps.get --only prod && mix deps.compile

# Application sources, generated browser assets, then the release.
COPY config config
COPY lib lib
COPY priv priv
COPY assets assets

# Builds the Tailwind stylesheet and copies the mix.lock-pinned Phoenix
# browser scripts into priv/static/assets (git-ignored output).
RUN mix assets.setup

RUN mix compile && mix release --path /app/release

# Runtime stage: smallest surface the BEAM needs, a non-root user, and curl
# for the loopback health probes. The listener stays on 127.0.0.1:4000 —
# see docs/KUBERNETES.md for the required in-pod reverse proxy.
FROM debian:bookworm-slim AS app

RUN apt-get update -y \
  && apt-get install -y --no-install-recommends ca-certificates curl libssl3 libstdc++6 \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --uid 1000 --create-home triage

ENV HOME=/tmp \
    RELEASE_TMP=/tmp \
    LANG=C.UTF-8 \
    PHX_SERVER=true \
    TRIAGE_BIND=127.0.0.1 \
    PORT=4000

WORKDIR /app
COPY --from=build --chown=triage:triage /app/release ./

USER triage

# Documentation only: the port is reachable inside the pod, not on the pod
# network. The proxy sidecar owns the platform-facing port.
EXPOSE 4000

# beam terminates gracefully on SIGTERM (init:stop).
ENTRYPOINT ["/app/bin/triage"]
CMD ["start"]
