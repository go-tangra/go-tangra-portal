##################################
# Stage 1: Build Go executable
##################################

FROM golang:1.25-alpine AS builder

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
    -o /src/bin/admin-server \
    ./app/admin/service/cmd/server

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
COPY --from=builder /src/bin/admin-server /app/bin/admin-server

# Copy configuration files
COPY --from=builder /src/app/admin/service/configs/ /app/configs/

# Copy OpenAPI assets if they exist
COPY --from=builder /src/app/admin/service/cmd/server/assets/ /app/assets/

# Create non-root user
RUN addgroup -g 1000 admin && \
    adduser -D -u 1000 -G admin admin && \
    chown -R admin:admin /app

# Create data directory
RUN mkdir -p /app/data && chown admin:admin /app/data

# Switch to non-root user
USER admin:admin

# Expose HTTP and gRPC ports
EXPOSE 8080 9000

# Set default command
CMD ["/app/bin/admin-server", "-c", "/app/configs"]

# Labels
LABEL org.opencontainers.image.title="Admin Service" \
      org.opencontainers.image.description="Go Wind Admin Service" \
      org.opencontainers.image.version="${APP_VERSION}"
