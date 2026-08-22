# Multi-stage production Dockerfile for AIROM Enterprise Gateway & Scanner
# ── Stage 1: Build ─────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo v1.0.0)" \
    -o /bin/airom ./cmd/airom

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S airom \
    && adduser -u 10001 -S airom -G airom

COPY --from=builder /bin/airom /usr/local/bin/airom

USER 10001:10001
WORKDIR /home/airom

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/airom", "version"] || exit 1

ENTRYPOINT ["/usr/local/bin/airom"]
CMD ["serve", "--port", "8080", "--host", "0.0.0.0"]
