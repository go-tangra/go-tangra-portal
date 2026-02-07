##################################
# Stage 1: Build Go executable
##################################

FROM golang:1.23-alpine AS builder

ARG APP_VERSION=1.0.0

# Enable toolchain auto-download for newer Go versions
ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the server
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags "-X main.version=${APP_VERSION} -s -w" \
    -o /src/bin/warden-server \
    ./app/warden/service/cmd/server

##################################
# Stage 2: Create runtime image
##################################

FROM alpine:3.20

ARG APP_VERSION=1.0.0

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Set timezone
ENV TZ=UTC

# Set working directory
WORKDIR /app

# Copy executable from builder
COPY --from=builder /src/bin/warden-server /app/bin/warden-server

# Copy configuration files
COPY --from=builder /src/app/warden/service/configs/ /app/configs/

# Create non-root user
RUN addgroup -g 1000 warden && \
    adduser -D -u 1000 -G warden warden && \
    chown -R warden:warden /app

# Switch to non-root user
USER warden:warden

# Expose gRPC port
EXPOSE 9300

# Set default command
CMD ["/app/bin/warden-server", "-c", "/app/configs"]

# Labels
LABEL org.opencontainers.image.title="Warden Service" \
      org.opencontainers.image.description="Secret Management Service with HashiCorp Vault" \
      org.opencontainers.image.version="${APP_VERSION}"
