##################################
# Stage 1: Build Go executables
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
    -o /src/bin/lcm-server \
    ./app/lcm/service/cmd/server

# Build the client
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags "-X main.version=${APP_VERSION} -s -w" \
    -o /src/bin/lcm-client \
    ./app/lcm/service/cmd/client

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

# Copy executables from builder
COPY --from=builder /src/bin/lcm-server /app/bin/lcm-server
COPY --from=builder /src/bin/lcm-client /app/bin/lcm-client

# Copy configuration files
COPY --from=builder /src/app/lcm/service/configs/ /app/configs/

# Create non-root user
RUN addgroup -g 1000 lcm && \
    adduser -D -u 1000 -G lcm lcm && \
    chown -R lcm:lcm /app

# Create data directory for certificates
RUN mkdir -p /app/data && chown lcm:lcm /app/data

# Switch to non-root user
USER lcm:lcm

# Expose gRPC port
EXPOSE 9100

# Set default command
CMD ["/app/bin/lcm-server", "-c", "/app/configs"]

# Labels
LABEL org.opencontainers.image.title="LCM Service" \
      org.opencontainers.image.description="Lifecycle Certificate Manager Service" \
      org.opencontainers.image.version="${APP_VERSION}"
