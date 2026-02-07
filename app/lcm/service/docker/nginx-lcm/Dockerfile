# Dockerfile for nginx with LCM client
# Used for e2e testing of certificate installation

# Build stage - compile the LCM client
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire backend source
COPY . .

# Build the LCM client
WORKDIR /build/app/lcm/service
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /lcm-client ./cmd/client

# Final stage - nginx with LCM client
FROM nginx:1.27-alpine

# Install useful tools for testing
RUN apk add --no-cache \
    bash \
    curl \
    openssl \
    ca-certificates \
    jq

# Copy LCM client from builder
COPY --from=builder /lcm-client /usr/local/bin/lcm-client
RUN chmod +x /usr/local/bin/lcm-client

# Create directories for LCM client
RUN mkdir -p /root/.lcm-client/live /root/.lcm-client/renewal

# Create a sample nginx config with a test server block
RUN mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# Create a test server configuration
RUN cat > /etc/nginx/conf.d/test-site.conf << 'EOF'
# Test site configuration for LCM e2e testing
server {
    listen 80;
    server_name test.example.com www.test.example.com;

    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }
}
EOF

# Create ACME challenge directory
RUN mkdir -p /var/www/acme/.well-known/acme-challenge

# Create a test HTML page
RUN cat > /usr/share/nginx/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>LCM Test Site</title>
</head>
<body>
    <h1>LCM Nginx Test Site</h1>
    <p>This site is used for testing LCM client nginx integration.</p>
</body>
</html>
EOF

# Create entrypoint script
RUN cat > /docker-entrypoint-lcm.sh << 'EOF'
#!/bin/bash
set -e

echo "=== LCM Nginx Test Container ==="
echo "Nginx version: $(nginx -v 2>&1)"
echo "LCM client version: $(lcm-client --version 2>/dev/null || echo 'unknown')"
echo ""

# If LCM_SERVER is set, configure the client
if [ -n "$LCM_SERVER" ]; then
    echo "LCM Server: $LCM_SERVER"

    # Create config file
    cat > /root/.lcm-client/config.yaml << EOFCFG
server: ${LCM_SERVER}
client-id: ${LCM_CLIENT_ID:-nginx-test}
EOFCFG
fi

# If certificates are provided via environment, save them
if [ -n "$LCM_CERT_PEM" ] && [ -n "$LCM_KEY_PEM" ]; then
    echo "Saving provided certificates..."
    CERT_NAME="${LCM_CERT_NAME:-test-cert}"
    mkdir -p "/root/.lcm-client/live/$CERT_NAME"
    echo "$LCM_CERT_PEM" > "/root/.lcm-client/live/$CERT_NAME/cert.pem"
    echo "$LCM_KEY_PEM" > "/root/.lcm-client/live/$CERT_NAME/privkey.pem"
    if [ -n "$LCM_CHAIN_PEM" ]; then
        echo "$LCM_CHAIN_PEM" > "/root/.lcm-client/live/$CERT_NAME/chain.pem"
        cat "/root/.lcm-client/live/$CERT_NAME/cert.pem" "/root/.lcm-client/live/$CERT_NAME/chain.pem" > "/root/.lcm-client/live/$CERT_NAME/fullchain.pem"
    else
        cp "/root/.lcm-client/live/$CERT_NAME/cert.pem" "/root/.lcm-client/live/$CERT_NAME/fullchain.pem"
    fi
    chmod 600 "/root/.lcm-client/live/$CERT_NAME"/*.pem
    echo "Certificate saved as: $CERT_NAME"
fi

# Start nginx in foreground or run custom command
if [ "$1" = "nginx" ] || [ -z "$1" ]; then
    echo "Starting nginx..."
    exec nginx -g "daemon off;"
else
    exec "$@"
fi
EOF
RUN chmod +x /docker-entrypoint-lcm.sh

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

ENTRYPOINT ["/docker-entrypoint-lcm.sh"]
CMD ["nginx"]
