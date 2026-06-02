# syntax=docker/dockerfile:1
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

RUN apk add --no-cache build-base make

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# With .dockerignore excluding .git, set the source revision at build time so the UI
# and "Access Server version" reflect the artifact. Example:
#   docker build --build-arg GIT_COMMIT=$(git rev-parse HEAD) -t netplug .
ARG GIT_COMMIT=
RUN CGO_ENABLED=1 GOOS=linux make build OUTPUT=/out/netplug GIT_COMMIT="${GIT_COMMIT}"

# CoreDNS for the optional DNS server (settings → DNS).
ARG COREDNS_VERSION=1.14.3
RUN set -eux; \
  arch="$(uname -m)"; \
  case "$arch" in \
    x86_64) coredns_arch=amd64 ;; \
    aarch64|arm64) coredns_arch=arm64 ;; \
    *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
  esac; \
  wget -qO /tmp/coredns.tgz "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_${coredns_arch}.tgz"; \
  tar -xzf /tmp/coredns.tgz -C /usr/local/bin coredns; \
  chmod +x /usr/local/bin/coredns; \
  rm /tmp/coredns.tgz

FROM alpine:3.21 AS runner

ENV DATA_DIR=/data
ENV SQLITE_PATH=/data/netplug.sqlite
ENV HTTP_ADDR=:8080

WORKDIR /app

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    sqlite \
    iproute2 \
    openresolv \
    ca-certificates

# Traffic control CLI: `/sbin/tc` is provided by Alpine's iproute2 (listed above).

EXPOSE 8080
EXPOSE 53/udp
EXPOSE 53/tcp

COPY --from=builder /out/netplug /usr/local/bin/netplug
COPY --from=builder /usr/local/bin/coredns /usr/local/bin/coredns
ENV COREDNS_BIN=/usr/local/bin/coredns
ENTRYPOINT ["netplug"]
