# Multi-stage build: static Go binary in a minimal, non-root runtime image.
# Images are tagged immutably in CI (git SHA on main, semver on releases —
# ADR-008); PR builds build but never publish.
#
# Build context is this service checkout, which is self-contained: the module,
# its packages, and the pinned canonical contract material it verifies at
# startup all live here.
#
#   docker build --build-arg VERSION=<sha> -t anvilkit-agent-service:<sha> services/agent-service
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/agent-service ./cmd/agent-service
# The protected-audit provisioner ships in the same image so the audit is
# established by exactly the code the service was built with, and it is a
# separate binary because it is a separate workload: it runs once with an
# administrative credential the service is never given, and exits.
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/protected-audit-provisioner ./cmd/protected-audit-provisioner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agent-service /agent-service
COPY --from=build /out/protected-audit-provisioner /usr/local/bin/protected-audit-provisioner

# The pinned canonical contract material is read from disk at startup and at
# the readiness boundary: the service verifies the local pin, the pinned
# profile and lock copies, and every canonical schema byte binding before it
# serves. ANVILKIT_CONTRACT_ROOT names the directory that *contains*
# `contracts/`, so the tree lands at /opt/anvilkit/contracts and the root is
# /opt/anvilkit.
#
# Only pin.json and the canonical agent material are copied. contracts/generated
# and contracts/validator are Go source compiled into the binary above; shipping
# them would put source in a runtime image for nothing.
COPY --from=build /src/contracts/pin.json /opt/anvilkit/contracts/pin.json
COPY --from=build /src/contracts/agent /opt/anvilkit/contracts/agent
ENV ANVILKIT_CONTRACT_ROOT=/opt/anvilkit

# Agent definitions, tool schemas, and database migrations are embedded in the
# binary, so nothing else is read from the image filesystem. The durable
# stream-cursor spool is the one path the service writes to and it is a mounted
# volume (ADR-024), which is what lets the root filesystem stay read-only.

# The service reports its own version from configuration rather than from a
# stamped symbol; the deployed ConfigMap does not set it, so this is the value
# a running instance reports.
ARG VERSION=dev
ENV ANVILKIT_SERVICE_VERSION=${VERSION}

# The authenticated Agent API. No separate metrics port: telemetry leaves over
# OTLP, not a scraped endpoint.
EXPOSE 8080
ENTRYPOINT ["/agent-service"]
