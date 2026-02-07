# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /echo-service ./app/echo/service/cmd/server

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary (OpenAPI spec is embedded)
COPY --from=builder /echo-service /app/echo-service

# Expose gRPC port
EXPOSE 9500

# Environment variables
ENV GRPC_ADDR=0.0.0.0:9500
ENV ADMIN_GRPC_ENDPOINT=admin-service:9000

# Run the service
CMD ["/app/echo-service"]
