#!/bin/bash
# LCM Service Functional Test Runner
#
# Usage:
#   ./run_tests.sh [test_name]
#
# Examples:
#   ./run_tests.sh                           # Run all tests
#   ./run_tests.sh TestClientRegistration    # Run specific test
#   ./run_tests.sh TestIssuerCreation        # Run issuer tests
#   ./run_tests.sh TestCertificateRequestFlow # Run certificate tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(cd "$TEST_DIR/../../../../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}LCM Service Functional Test Runner${NC}"
echo "========================================"

# Check required environment variables
check_env() {
    local var_name=$1
    local required=$2
    local value="${!var_name}"

    if [ -z "$value" ]; then
        if [ "$required" = "required" ]; then
            echo -e "${RED}ERROR: $var_name is not set${NC}"
            return 1
        else
            echo -e "${YELLOW}WARNING: $var_name is not set (optional)${NC}"
        fi
    else
        echo -e "${GREEN}✓${NC} $var_name is set"
    fi
    return 0
}

echo ""
echo "Checking environment variables..."
echo ""

# Required for all tests
check_env "LCM_TEST_CA_FILE" "required" || exit 1
check_env "LCM_TEST_SHARED_SECRET" "required" || exit 1

# Optional
check_env "LCM_TEST_SERVER" "optional"
check_env "LCM_TEST_CONFIG" "optional"
check_env "LCM_TEST_CLIENT_CERT" "optional"
check_env "LCM_TEST_CLIENT_KEY" "optional"
check_env "LCM_TEST_ISSUER_NAME" "optional"
check_env "LCM_TEST_OUTPUT_DIR" "optional"

# Set defaults
export LCM_TEST_SERVER="${LCM_TEST_SERVER:-localhost:9100}"

echo ""
echo "Test Configuration:"
echo "  Server:      $LCM_TEST_SERVER"
echo "  CA File:     $LCM_TEST_CA_FILE"
echo "  Config:      ${LCM_TEST_CONFIG:-testdata/dns_config.yaml}"
echo ""

# Check if CA file exists
if [ ! -f "$LCM_TEST_CA_FILE" ]; then
    echo -e "${RED}ERROR: CA file not found: $LCM_TEST_CA_FILE${NC}"
    exit 1
fi

# Check if DNS config exists (if specified)
if [ -n "$LCM_TEST_CONFIG" ] && [ ! -f "$LCM_TEST_CONFIG" ]; then
    echo -e "${YELLOW}WARNING: DNS config file not found: $LCM_TEST_CONFIG${NC}"
fi

# Check default DNS config
DEFAULT_DNS_CONFIG="$TEST_DIR/testdata/dns_config.yaml"
if [ -z "$LCM_TEST_CONFIG" ] && [ ! -f "$DEFAULT_DNS_CONFIG" ]; then
    echo -e "${YELLOW}WARNING: Default DNS config not found at $DEFAULT_DNS_CONFIG${NC}"
    echo -e "${YELLOW}Copy dns_config.example.yaml to dns_config.yaml and configure it${NC}"
fi

# Change to project root for running tests
cd "$PROJECT_ROOT"

# Build test filter
TEST_FILTER=""
if [ -n "$1" ]; then
    TEST_FILTER="-run $1"
    echo "Running test: $1"
else
    echo "Running all functional tests"
fi

echo ""
echo "========================================"
echo ""

# Run the tests
go test -v $TEST_FILTER ./app/lcm/service/test/functional/... 2>&1 | tee /tmp/lcm_test_output.log

# Check result
TEST_RESULT=${PIPESTATUS[0]}

echo ""
echo "========================================"

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed. Check output above.${NC}"
    exit 1
fi
