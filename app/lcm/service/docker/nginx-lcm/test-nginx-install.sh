#!/bin/bash
# E2E test script for LCM client nginx integration
# This script demonstrates how to test the nginx SSL installation feature

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="nginx-lcm-test"

echo "=== LCM Nginx Integration E2E Test ==="
echo ""

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Starting nginx-lcm container..."
    cd "$SCRIPT_DIR"
    docker compose up -d --build
    echo "Waiting for container to be healthy..."
    sleep 5
fi

echo "Container status:"
docker ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo ""

# Test 1: Check nginx discovery
echo "=== Test 1: Nginx Discovery ==="
docker exec ${CONTAINER_NAME} lcm-client nginx info
echo ""

# Test 2: Check nginx status
echo "=== Test 2: Nginx Status ==="
docker exec ${CONTAINER_NAME} lcm-client nginx status
echo ""

# Test 3: List certificates (should be empty initially)
echo "=== Test 3: List Certificates ==="
docker exec ${CONTAINER_NAME} lcm-client nginx list-certs
echo ""

# Test 4: Create a self-signed test certificate
echo "=== Test 4: Create Test Certificate ==="
docker exec ${CONTAINER_NAME} bash -c '
CERT_NAME="test.example.com"
CERT_DIR="/root/.lcm-client/live/$CERT_NAME"
mkdir -p "$CERT_DIR"

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/cert.pem" \
    -subj "/CN=test.example.com/O=LCM Test/C=US" \
    -addext "subjectAltName=DNS:test.example.com,DNS:www.test.example.com" 2>/dev/null

# Create fullchain (same as cert for self-signed)
cp "$CERT_DIR/cert.pem" "$CERT_DIR/fullchain.pem"

# Create metadata
cat > "/root/.lcm-client/renewal/$CERT_NAME.json" << EOF
{
  "name": "$CERT_NAME",
  "common_name": "test.example.com",
  "serial_number": "test-serial-001",
  "issued_at": "$(date -Iseconds)",
  "expires_at": "$(date -d "+365 days" -Iseconds 2>/dev/null || date -v+365d -Iseconds)",
  "dns_names": ["test.example.com", "www.test.example.com"],
  "renewal_count": 0
}
EOF

chmod 600 "$CERT_DIR"/*.pem
echo "Created test certificate: $CERT_NAME"
'
echo ""

# Test 5: List certificates again
echo "=== Test 5: List Certificates (after creation) ==="
docker exec ${CONTAINER_NAME} lcm-client nginx list-certs
echo ""

# Test 6: Dry-run install
echo "=== Test 6: Dry-Run Install ==="
docker exec ${CONTAINER_NAME} lcm-client nginx install \
    --cert-name test.example.com \
    --dry-run
echo ""

# Test 7: Actual install
echo "=== Test 7: Actual Install ==="
read -p "Do you want to perform the actual SSL installation? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker exec ${CONTAINER_NAME} lcm-client nginx install \
        --cert-name test.example.com \
        --http2 \
        --hsts
    echo ""

    # Test 8: Verify nginx status after install
    echo "=== Test 8: Nginx Status (after install) ==="
    docker exec ${CONTAINER_NAME} lcm-client nginx status
    echo ""

    # Test 9: Test HTTPS connection
    echo "=== Test 9: Test HTTPS Connection ==="
    echo "Testing HTTPS on port 8443..."
    curl -k -v https://localhost:8443/ 2>&1 | head -30 || echo "Note: Connection may fail if nginx hasn't reloaded"
fi

echo ""
echo "=== E2E Test Complete ==="
echo ""
echo "Manual testing commands:"
echo "  docker exec -it ${CONTAINER_NAME} bash"
echo "  docker exec ${CONTAINER_NAME} lcm-client nginx info"
echo "  docker exec ${CONTAINER_NAME} lcm-client nginx status"
echo "  docker exec ${CONTAINER_NAME} nginx -t"
echo "  docker exec ${CONTAINER_NAME} cat /etc/nginx/conf.d/test-site.conf"
echo ""
echo "Cleanup:"
echo "  docker compose -f $SCRIPT_DIR/docker-compose.yaml down -v"
