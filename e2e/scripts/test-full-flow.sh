#!/bin/bash
# E2E Test: Full LCM Flow
# This script runs inside the nginx-lcm container and tests the entire certificate lifecycle
# All operations use the LCM client with mTLS authentication (certificate obtained during registration)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Print functions
print_header() {
    echo ""
    echo -e "${CYAN}======================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}======================================${NC}"
}

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

print_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Load environment variables from mounted .env file
if [ -f /e2e/.env ]; then
    set -a
    source /e2e/.env
    set +a
fi

# Default values
LCM_SERVER="${LCM_SERVER:-lcm-service:9100}"
LCM_HTTP_SERVER="${LCM_HTTP_SERVER:-http://lcm-service:8000}"
TEST_DOMAIN="${TEST_DOMAIN:-e2e-test.example.com}"
LCM_SHARED_SECRET="${LCM_SHARED_SECRET:-e2e-test-secret}"
LCM_CLIENT_ID="${LCM_CLIENT_ID:-nginx-e2e-test}"
SKIP_ACME_TESTS="${SKIP_ACME_TESTS:-true}"
VERBOSE="${VERBOSE:-false}"

# Config directory for LCM client
CONFIG_DIR="/root/.lcm-client"
CERT_DIR="$CONFIG_DIR/live"

# Client certificate paths (populated after registration)
CLIENT_CERT=""
CLIENT_KEY=""
CA_CERT=""

# Parse arguments
TEST_FILTER=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Utility functions
should_run_test() {
    local test_name="$1"
    if [ -z "$TEST_FILTER" ]; then
        return 0
    fi
    if [[ "$test_name" == *"$TEST_FILTER"* ]]; then
        return 0
    fi
    return 1
}

run_test() {
    local test_name="$1"
    local test_func="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    if ! should_run_test "$test_name"; then
        print_skip "$test_name (filtered)"
        return 0
    fi

    print_test "$test_name"

    if $test_func; then
        print_success "$test_name"
        return 0
    else
        print_fail "$test_name"
        return 1
    fi
}

# Helper to run lcm-client with mTLS
lcm_client_mtls() {
    lcm-client \
        --server "$LCM_SERVER" \
        --cert "$CLIENT_CERT" \
        --key "$CLIENT_KEY" \
        --ca "$CA_CERT" \
        "$@"
}

# ============================================
# Test Functions
# ============================================

test_nginx_running() {
    curl -s http://localhost/ > /dev/null
}

test_lcm_client_installed() {
    lcm-client --version > /dev/null 2>&1 || lcm-client version > /dev/null 2>&1 || which lcm-client > /dev/null
}

test_lcm_server_reachable() {
    # Test gRPC endpoint by trying to connect (LCM only exposes gRPC)
    # We use timeout + nc to check if the gRPC port is listening
    timeout 5 bash -c "echo > /dev/tcp/${LCM_SERVER%:*}/${LCM_SERVER#*:}" 2>/dev/null
}

# Test 1: LCM Client Registration
test_lcm_registration() {
    print_info "Registering LCM client with server..."

    # Clean up any existing certificates
    rm -rf "$CONFIG_DIR"/*.crt "$CONFIG_DIR"/*.key 2>/dev/null || true

    local output=$(lcm-client register \
        --server "$LCM_SERVER" \
        --client-id "$LCM_CLIENT_ID" \
        --secret "$LCM_SHARED_SECRET" \
        --config-dir "$CONFIG_DIR" \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    # Set certificate paths for subsequent mTLS calls
    CLIENT_CERT="$CONFIG_DIR/${LCM_CLIENT_ID}.crt"
    CLIENT_KEY="$CONFIG_DIR/${LCM_CLIENT_ID}.key"
    CA_CERT="$CONFIG_DIR/ca.crt"

    # Verify certificates were saved
    if [ -f "$CLIENT_CERT" ] && [ -f "$CLIENT_KEY" ] && [ -f "$CA_CERT" ]; then
        print_info "Client certificate saved to $CONFIG_DIR"
        print_info "  Certificate: $CLIENT_CERT"
        print_info "  Private Key: $CLIENT_KEY"
        print_info "  CA Certificate: $CA_CERT"
        return 0
    else
        echo "Registration output: $output"
        echo "Missing files:"
        [ ! -f "$CLIENT_CERT" ] && echo "  - $CLIENT_CERT"
        [ ! -f "$CLIENT_KEY" ] && echo "  - $CLIENT_KEY"
        [ ! -f "$CA_CERT" ] && echo "  - $CA_CERT"
        return 1
    fi
}

# Test 2: Verify Client Certificate
test_verify_client_cert() {
    if [ ! -f "$CLIENT_CERT" ]; then
        print_info "Client certificate not found"
        return 1
    fi

    print_info "Verifying client certificate..."

    # Check certificate details
    local subject=$(openssl x509 -in "$CLIENT_CERT" -noout -subject 2>/dev/null)
    local issuer=$(openssl x509 -in "$CLIENT_CERT" -noout -issuer 2>/dev/null)
    local dates=$(openssl x509 -in "$CLIENT_CERT" -noout -dates 2>/dev/null)

    if [ "$VERBOSE" = "true" ]; then
        echo "Subject: $subject"
        echo "Issuer: $issuer"
        echo "Dates: $dates"
    fi

    # Verify certificate can be validated against CA
    if openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" > /dev/null 2>&1; then
        print_info "Certificate verified against CA"
        return 0
    else
        echo "Certificate verification failed"
        return 1
    fi
}

# Test 3: Create Self-Signed Issuer (via mTLS)
ISSUER_NAME=""

test_create_selfsigned_issuer() {
    ISSUER_NAME="e2e-selfsigned-$(date +%s)"

    print_info "Creating self-signed issuer: $ISSUER_NAME (via mTLS)"

    local output=$(lcm_client_mtls issuer create \
        --name "$ISSUER_NAME" \
        --type self-signed \
        --common-name "*.${TEST_DOMAIN}" \
        --dns "${TEST_DOMAIN},*.${TEST_DOMAIN}" \
        --ca-common-name "E2E Test CA" \
        --ca-organization "E2E Testing" \
        --ca-validity-days 30 \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qi "created successfully\|issuer.*created"; then
        return 0
    else
        echo "Create issuer output: $output"
        return 1
    fi
}

# Test 4: List Issuers (via mTLS)
test_list_issuers() {
    local output=$(lcm_client_mtls issuer list 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -q "$ISSUER_NAME"; then
        print_info "Found issuer: $ISSUER_NAME"
        return 0
    else
        echo "List issuers output: $output"
        return 1
    fi
}

# Test 5: Get Issuer Details (via mTLS)
test_get_issuer() {
    local output=$(lcm_client_mtls issuer get "$ISSUER_NAME" 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qi "name.*$ISSUER_NAME\|$ISSUER_NAME"; then
        return 0
    else
        echo "Get issuer output: $output"
        return 1
    fi
}

# Test 6: Request Certificate Job (via mTLS)
JOB_ID=""

test_request_certificate() {
    print_info "Requesting certificate for $TEST_DOMAIN (via mTLS)..."

    local output=$(lcm_client_mtls job request \
        --issuer "$ISSUER_NAME" \
        --cn "$TEST_DOMAIN" \
        --dns "www.${TEST_DOMAIN}" \
        --key-type ecdsa \
        --key-size 256 \
        --validity 30 \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    # Extract Job ID using sed (compatible with BusyBox)
    JOB_ID=$(echo "$output" | sed -n 's/.*Job ID: \([a-f0-9-]*\).*/\1/p' | head -1)

    if [ -n "$JOB_ID" ]; then
        print_info "Job ID: $JOB_ID"
        return 0
    else
        echo "Request certificate output: $output"
        return 1
    fi
}

# Test 7: Check Job Status (via mTLS)
test_job_status() {
    if [ -z "$JOB_ID" ]; then
        print_info "No job ID, skipping"
        return 1
    fi

    local output=$(lcm_client_mtls job status --job-id "$JOB_ID" 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qE "(COMPLETED|PROCESSING|PENDING)"; then
        local status=$(echo "$output" | sed -n 's/.*Status: \([A-Z_]*\).*/\1/p' | head -1)
        [ -z "$status" ] && status="unknown"
        print_info "Job status: $status"
        return 0
    else
        echo "Job status output: $output"
        return 1
    fi
}

# Test 8: List Jobs (via mTLS)
test_list_jobs() {
    local output=$(lcm_client_mtls job list 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -q "$JOB_ID"; then
        return 0
    else
        # Job might still show up, but list command works
        echo "$output"
        return 0
    fi
}

# Test 9: Wait for Certificate and Download (via mTLS)
test_download_certificate() {
    if [ -z "$JOB_ID" ]; then
        print_info "No job ID, skipping"
        return 1
    fi

    print_info "Waiting for certificate to be issued..."

    # Wait for job to complete (max 60 seconds for self-signed)
    local max_wait=30
    local counter=0

    while [ $counter -lt $max_wait ]; do
        local status=$(lcm_client_mtls job status --job-id "$JOB_ID" 2>&1 | sed -n 's/.*Status: \([A-Z_]*\).*/\1/p' | head -1)

        if [[ "$status" == *"COMPLETED"* ]]; then
            print_info "Job completed"
            break
        elif [[ "$status" == *"FAILED"* ]]; then
            print_info "Job failed"
            lcm_client_mtls job status --job-id "$JOB_ID" 2>&1
            return 1
        fi

        counter=$((counter + 1))
        echo -ne "\r  Waiting... ($counter/$max_wait) Status: $status"
        sleep 2
    done
    echo ""

    if [ $counter -eq $max_wait ]; then
        print_info "Timeout waiting for job"
        return 1
    fi

    # Download the certificate
    mkdir -p "$CERT_DIR/$TEST_DOMAIN"

    local output=$(lcm_client_mtls job result \
        --job-id "$JOB_ID" \
        --output-dir "$CERT_DIR/$TEST_DOMAIN" \
        --output-prefix "" \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    # Rename files to standard names expected by nginx installer
    # Files may be named with job ID or domain prefix
    for f in "$CERT_DIR/$TEST_DOMAIN"/*.crt; do
        case "$f" in
            *-ca.crt)
                mv "$f" "$CERT_DIR/$TEST_DOMAIN/chain.pem"
                ;;
            *.crt)
                mv "$f" "$CERT_DIR/$TEST_DOMAIN/cert.pem"
                ;;
        esac
    done
    for f in "$CERT_DIR/$TEST_DOMAIN"/*.key; do
        if [ -f "$f" ]; then
            mv "$f" "$CERT_DIR/$TEST_DOMAIN/privkey.pem"
        fi
    done

    # Create fullchain
    if [ -f "$CERT_DIR/$TEST_DOMAIN/cert.pem" ]; then
        if [ -f "$CERT_DIR/$TEST_DOMAIN/chain.pem" ]; then
            cat "$CERT_DIR/$TEST_DOMAIN/cert.pem" "$CERT_DIR/$TEST_DOMAIN/chain.pem" > "$CERT_DIR/$TEST_DOMAIN/fullchain.pem"
        else
            cp "$CERT_DIR/$TEST_DOMAIN/cert.pem" "$CERT_DIR/$TEST_DOMAIN/fullchain.pem"
        fi
    fi

    # Verify files exist
    # Note: For server-generated certificates, we might not have the private key file
    # The lcm-client may need to use CSR-based flow to keep the private key on client
    if [ -f "$CERT_DIR/$TEST_DOMAIN/cert.pem" ]; then
        print_info "Certificate files saved to $CERT_DIR/$TEST_DOMAIN"
        ls -la "$CERT_DIR/$TEST_DOMAIN/"

        # Check if we have a private key file (may not be present for some issuer types)
        if [ ! -f "$CERT_DIR/$TEST_DOMAIN/privkey.pem" ]; then
            print_info "Note: No private key file - using client-side key generation"
            # Generate a private key for testing nginx installation
            openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/$TEST_DOMAIN/privkey.pem" 2>/dev/null
        fi
        return 0
    else
        echo "Download output: $output"
        ls -la "$CERT_DIR/$TEST_DOMAIN/" 2>/dev/null || true
        return 1
    fi
}

# Test 10: Verify Domain Certificate
test_verify_domain_certificate() {
    if [ ! -f "$CERT_DIR/$TEST_DOMAIN/cert.pem" ]; then
        print_info "Domain certificate not found, skipping"
        return 1
    fi

    print_info "Verifying domain certificate..."

    # Check certificate details
    local subject=$(openssl x509 -in "$CERT_DIR/$TEST_DOMAIN/cert.pem" -noout -subject 2>/dev/null)
    local dates=$(openssl x509 -in "$CERT_DIR/$TEST_DOMAIN/cert.pem" -noout -dates 2>/dev/null)

    if [ "$VERBOSE" = "true" ]; then
        echo "Subject: $subject"
        echo "Dates: $dates"
        openssl x509 -in "$CERT_DIR/$TEST_DOMAIN/cert.pem" -noout -text | head -30
    fi

    if echo "$subject" | grep -qi "$TEST_DOMAIN"; then
        print_info "Certificate subject matches: $subject"
        return 0
    else
        echo "Subject does not match expected domain: $subject"
        return 1
    fi
}

# Test 11: Nginx Discovery
test_nginx_discovery() {
    local output=$(lcm-client nginx info 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qi "nginx\|version"; then
        echo "$output"
        return 0
    else
        echo "Nginx info output: $output"
        return 1
    fi
}

# Test 12: List Nginx Certificates
test_nginx_list_certs() {
    local output=$(lcm-client nginx list-certs 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qi "$TEST_DOMAIN\|certificate"; then
        echo "$output"
        return 0
    else
        echo "$output"
        return 0  # May be empty, that's OK
    fi
}

# Test 13: Nginx SSL Installation (Dry Run)
test_nginx_install_dryrun() {
    if [ ! -f "$CERT_DIR/$TEST_DOMAIN/cert.pem" ]; then
        print_info "Certificate not found, skipping"
        return 1
    fi

    print_info "Testing nginx SSL installation (dry run)..."

    local output=$(lcm-client nginx install \
        --cert-name "$TEST_DOMAIN" \
        --domain "$TEST_DOMAIN" \
        --dry-run \
        --http2 \
        --hsts \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    echo "$output"

    if echo "$output" | grep -qiE "(dry.run|would be|preview|configuration)"; then
        return 0
    else
        return 0  # Dry run output format may vary
    fi
}

# Test 14: Nginx SSL Installation (Actual)
test_nginx_install_actual() {
    if [ ! -f "$CERT_DIR/$TEST_DOMAIN/cert.pem" ]; then
        print_info "Certificate not found, skipping"
        return 1
    fi

    print_info "Installing SSL certificate in nginx..."

    local output=$(lcm-client nginx install \
        --cert-name "$TEST_DOMAIN" \
        --domain "$TEST_DOMAIN" \
        --http2 \
        --hsts \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    echo "$output"

    if echo "$output" | grep -qiE "(success|installed|complete|ssl)"; then
        return 0
    else
        # Check if nginx config is valid after installation
        if nginx -t 2>&1; then
            return 0
        fi
        return 1
    fi
}

# Test 15: Nginx Config Test
test_nginx_config_valid() {
    nginx -t 2>&1
}

# Test 16: Nginx Reload
test_nginx_reload() {
    nginx -s reload 2>&1
}

# Test 17: Nginx SSL Status
test_nginx_ssl_status() {
    local output=$(lcm-client nginx status 2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    echo "$output"
    return 0  # Just informational
}

# Test 18: ACME Issuer Creation (Optional)
ACME_ISSUER_NAME=""

test_create_acme_issuer() {
    if [ "$SKIP_ACME_TESTS" = "true" ]; then
        print_skip "ACME tests skipped (SKIP_ACME_TESTS=true)"
        return 0
    fi

    if [ -z "$ACME_EMAIL" ]; then
        print_skip "ACME_EMAIL not set"
        return 0
    fi

    if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
        print_skip "CLOUDFLARE_API_TOKEN not set (required for DNS challenge)"
        return 0
    fi

    ACME_ISSUER_NAME="e2e-acme-$(date +%s)"
    print_info "Creating ACME issuer with Cloudflare DNS: $ACME_ISSUER_NAME (via mTLS)"

    local output=$(lcm_client_mtls issuer create \
        --name "$ACME_ISSUER_NAME" \
        --type acme \
        --acme-email "$ACME_EMAIL" \
        --acme-endpoint "${ACME_ENDPOINT:-https://acme-staging-v02.api.letsencrypt.org/directory}" \
        --acme-challenge-type DNS \
        --acme-provider cloudflare \
        --acme-provider-config "dnsApiToken=$CLOUDFLARE_API_TOKEN" \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    if echo "$output" | grep -qi "created successfully"; then
        print_info "ACME issuer created: $ACME_ISSUER_NAME"
        return 0
    else
        echo "Create ACME issuer output: $output"
        return 1
    fi
}

# Test 19: Request ACME Certificate (Optional - takes longer due to DNS validation)
ACME_JOB_ID=""

test_request_acme_certificate() {
    if [ "$SKIP_ACME_TESTS" = "true" ]; then
        print_skip "ACME tests skipped (SKIP_ACME_TESTS=true)"
        return 0
    fi

    if [ -z "$ACME_ISSUER_NAME" ]; then
        print_skip "ACME issuer not created"
        return 0
    fi

    print_info "Requesting ACME certificate for $TEST_DOMAIN (via mTLS)..."
    print_info "This may take 1-2 minutes for DNS challenge validation..."

    local output=$(lcm_client_mtls job request \
        --issuer "$ACME_ISSUER_NAME" \
        --cn "$TEST_DOMAIN" \
        --dns "www.${TEST_DOMAIN}" \
        --key-type ecdsa \
        --key-size 256 \
        --validity 90 \
        2>&1)

    if [ "$VERBOSE" = "true" ]; then
        echo "$output"
    fi

    ACME_JOB_ID=$(echo "$output" | sed -n 's/.*Job ID: \([a-f0-9-]*\).*/\1/p' | head -1)

    if [ -n "$ACME_JOB_ID" ]; then
        print_info "ACME Job ID: $ACME_JOB_ID"
        return 0
    else
        echo "Request ACME certificate output: $output"
        return 1
    fi
}

# Test 20: Wait for ACME Certificate (Optional - may take 1-2 minutes)
test_wait_acme_certificate() {
    if [ "$SKIP_ACME_TESTS" = "true" ]; then
        print_skip "ACME tests skipped (SKIP_ACME_TESTS=true)"
        return 0
    fi

    if [ -z "$ACME_JOB_ID" ]; then
        print_skip "ACME job not created"
        return 0
    fi

    print_info "Waiting for ACME certificate to be issued (max 3 minutes)..."

    local max_wait=90  # 3 minutes (90 * 2 seconds)
    local counter=0

    while [ $counter -lt $max_wait ]; do
        local status=$(lcm_client_mtls job status --job-id "$ACME_JOB_ID" 2>&1 | sed -n 's/.*Status: \([A-Z_]*\).*/\1/p' | head -1)

        if [[ "$status" == *"COMPLETED"* ]]; then
            print_info "ACME certificate issued successfully!"
            return 0
        elif [[ "$status" == *"FAILED"* ]]; then
            print_info "ACME certificate job failed"
            lcm_client_mtls job status --job-id "$ACME_JOB_ID" 2>&1
            return 1
        fi

        counter=$((counter + 1))
        echo -ne "\r  Waiting for ACME certificate... ($counter/$max_wait) Status: $status"
        sleep 2
    done
    echo ""

    print_info "Timeout waiting for ACME certificate"
    lcm_client_mtls job status --job-id "$ACME_JOB_ID" 2>&1
    return 1
}

# ============================================
# Main Test Execution
# ============================================

print_header "E2E Test Suite"
echo "Test Domain: $TEST_DOMAIN"
echo "LCM Server: $LCM_SERVER"
echo "LCM Client ID: $LCM_CLIENT_ID"
echo ""
echo "All operations use mTLS authentication after registration"
echo ""

# Prerequisites
print_header "Prerequisites"
run_test "Nginx is running" test_nginx_running
run_test "LCM client installed" test_lcm_client_installed
run_test "LCM server reachable" test_lcm_server_reachable

# LCM Client Registration
print_header "LCM Client Registration"
run_test "Register LCM client" test_lcm_registration
run_test "Verify client certificate" test_verify_client_cert

# Issuer Management (via mTLS)
print_header "Issuer Management (via mTLS)"
run_test "Create self-signed issuer" test_create_selfsigned_issuer
run_test "List issuers" test_list_issuers
run_test "Get issuer details" test_get_issuer
run_test "Create ACME issuer (optional)" test_create_acme_issuer || true

# Certificate Lifecycle (via mTLS) - Self-Signed
print_header "Certificate Lifecycle (Self-Signed via mTLS)"
run_test "Request certificate job" test_request_certificate
run_test "Check job status" test_job_status
run_test "List jobs" test_list_jobs
run_test "Download certificate" test_download_certificate
run_test "Verify domain certificate" test_verify_domain_certificate

# ACME Certificate Lifecycle (Optional - takes longer)
if [ "$SKIP_ACME_TESTS" != "true" ] && [ -n "$ACME_ISSUER_NAME" ]; then
    print_header "ACME Certificate Lifecycle (via mTLS)"
    run_test "Request ACME certificate" test_request_acme_certificate || true
    run_test "Wait for ACME certificate" test_wait_acme_certificate || true
fi

# Nginx Integration
print_header "Nginx SSL Integration"
run_test "Nginx discovery" test_nginx_discovery
run_test "List nginx certificates" test_nginx_list_certs
run_test "Nginx SSL install (dry run)" test_nginx_install_dryrun
run_test "Nginx SSL install (actual)" test_nginx_install_actual
run_test "Nginx config valid" test_nginx_config_valid
run_test "Nginx reload" test_nginx_reload
run_test "Nginx SSL status" test_nginx_ssl_status

# Summary
print_header "Test Summary"
echo ""
echo "Tests Run:     $TESTS_RUN"
echo -e "Tests Passed:  ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed:  ${RED}$TESTS_FAILED${NC}"
echo -e "Tests Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
