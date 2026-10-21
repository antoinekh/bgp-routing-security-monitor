# raven (BGP routing security monitor) container image.
#
# Builds the `raven` binary from this checkout and ships the static binary on a
# slim alpine base. RAVEN is a single-binary BGP routing security monitor: BMP +
# RPKI ROV + ASPA path validation, with a Prometheus exporter and an
# events/webhook engine.
#
#   docker build -t raven .
#
# VERSION, COMMIT and DATE feed internal/buildinfo, which `raven version`, the
# startup log and `raven status` report.

# ---- build stage ----------------------------------------------------------
# Build on the runner platform and cross-compile for TARGETOS/TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

WORKDIR /src

# Dependencies first so the module cache layer survives source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN MODULE=$(head -1 go.mod | awk '{print $2}') && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w \
        -X ${MODULE}/internal/buildinfo.Version=${VERSION} \
        -X ${MODULE}/internal/buildinfo.Commit=${COMMIT} \
        -X ${MODULE}/internal/buildinfo.Date=${DATE}" \
      -o /out/raven ./cmd/raven && \
    mkdir -p /out/empty

# ---- runtime stage --------------------------------------------------------
FROM alpine:3.24

# Copy the CA bundle from the build stage so the runtime stage needs no RUN
# and no QEMU for arm64.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/raven /usr/local/bin/raven
COPY --from=build --chown=10001:10001 /out/empty /var/lib/raven

# Warm-start snapshots use ~/.raven/snapshots, so HOME must be writable.
ENV HOME=/var/lib/raven
WORKDIR /var/lib/raven
USER 10001:10001

EXPOSE 11019 11020 9595
ENTRYPOINT ["raven"]
