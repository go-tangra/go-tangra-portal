# Build stage
FROM golang:1.25-alpine AS builder

ARG APP_VERSION=1.0.0

# Enable toolchain auto-download for newer Go versions
ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /src

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
WORKDIR /src/app/deployer/service
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${APP_VERSION}" \
    -o /deployer-server ./cmd/server

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

WORKDIR /app

# Copy binary
COPY --from=builder /deployer-server .

# Copy config files
COPY app/deployer/service/configs ./configs

# Set ownership
RUN chown -R appuser:appuser /app

USER appuser

# Expose gRPC port
EXPOSE 9200

ENTRYPOINT ["/app/deployer-server"]
CMD ["-c", "/app/configs"]
