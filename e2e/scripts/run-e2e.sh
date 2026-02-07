#!/bin/bash
# E2E Test Runner
# This script sets up a clean test environment and runs the full E2E test suite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$E2E_DIR/docker-compose.e2e.yaml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print with color
print_step() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Load environment variables
if [ -f "$E2E_DIR/.env" ]; then
    print_step "Loading environment variables from .env"
    set -a
    source "$E2E_DIR/.env"
    set +a
else
    print_warning "No .env file found, using defaults"
    print_warning "Copy .env.example to .env to configure tests"
fi

# Parse command line arguments
CLEAN_START=true
BUILD_IMAGES=true
RUN_TESTS=true
KEEP_RUNNING=false
TEST_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-clean)
            CLEAN_START=false
            shift
            ;;
        --no-build)
            BUILD_IMAGES=false
            shift
            ;;
        --no-tests)
            RUN_TESTS=false
            shift
            ;;
        --keep-running)
            KEEP_RUNNING=true
            shift
            ;;
        --filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --no-clean      Don't clean up before starting (reuse existing volumes)"
            echo "  --no-build      Don't rebuild images"
            echo "  --no-tests      Just start services, don't run tests"
            echo "  --keep-running  Keep services running after tests"
            echo "  --filter NAME   Only run tests matching NAME"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo ""
echo "=============================================="
echo "       E2E Test Suite - Full Stack Test"
echo "=============================================="
echo ""

# Step 1: Clean up (if requested)
if [ "$CLEAN_START" = true ]; then
    print_step "Cleaning up previous test environment..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    print_success "Cleanup complete"
fi

# Step 2: Build images (if requested)
if [ "$BUILD_IMAGES" = true ]; then
    print_step "Building Docker images..."
    docker compose -f "$COMPOSE_FILE" build --parallel
    print_success "Images built"
fi

# Step 3: Start services
print_step "Starting services..."
docker compose -f "$COMPOSE_FILE" up -d

# Step 4: Wait for services to be ready
print_step "Waiting for services to be healthy..."

wait_for_service() {
    local service=$1
    local max_wait=${2:-120}
    local counter=0

    while [ $counter -lt $max_wait ]; do
        # docker compose ps --format json outputs one JSON object per line, not an array
        # Use -a flag to include exited containers (for init containers)
        # Note: .Health can be "" (empty string), which doesn't trigger //, so we check both Health and State
        local json_output
        json_output=$(docker compose -f "$COMPOSE_FILE" ps -a --format json "$service" 2>/dev/null | head -1)

        if [ -z "$json_output" ]; then
            counter=$((counter + 1))
            echo -ne "\r  Waiting for $service... ($counter/$max_wait)"
            sleep 2
            continue
        fi

        local health state
        health=$(echo "$json_output" | jq -r '.Health' 2>/dev/null || echo "")
        state=$(echo "$json_output" | jq -r '.State' 2>/dev/null || echo "unknown")

        # Use health if available and not empty, otherwise use state
        local status="$health"
        if [ -z "$status" ]; then
            status="$state"
        fi

        if [ "$status" = "healthy" ]; then
            print_success "$service is healthy"
            return 0
        elif [ "$status" = "exited" ]; then
            # Check if it's an init container that should exit
            local exit_code
            exit_code=$(echo "$json_output" | jq -r '.ExitCode' 2>/dev/null || echo "0")
            if [ "$exit_code" = "0" ]; then
                print_success "$service completed successfully"
                return 0
            else
                print_error "$service exited with code $exit_code"
                docker compose -f "$COMPOSE_FILE" logs "$service" | tail -20
                return 1
            fi
        fi

        counter=$((counter + 1))
        echo -ne "\r  Waiting for $service... ($counter/$max_wait)"
        sleep 2
    done

    echo ""
    print_error "Timeout waiting for $service"
    docker compose -f "$COMPOSE_FILE" logs "$service" | tail -30
    return 1
}

# Wait for all services
wait_for_service "postgres" 60
wait_for_service "redis" 60
wait_for_service "lcm-service" 120
wait_for_service "lcm-init" 120
wait_for_service "admin-service" 120
wait_for_service "deployer-service" 120
wait_for_service "db-init" 120
wait_for_service "nginx-lcm" 60

print_success "All services are ready!"

# Step 5: Run tests (if requested)
if [ "$RUN_TESTS" = true ]; then
    print_step "Running E2E tests..."
    echo ""

    # Run the test script inside the nginx-lcm container
    TEST_CMD="/e2e/test-full-flow.sh"
    if [ -n "$TEST_FILTER" ]; then
        TEST_CMD="$TEST_CMD --filter $TEST_FILTER"
    fi

    if docker compose -f "$COMPOSE_FILE" exec -T nginx-lcm $TEST_CMD; then
        echo ""
        print_success "All E2E tests passed!"
        TEST_RESULT=0
    else
        echo ""
        print_error "E2E tests failed!"
        TEST_RESULT=1
    fi
else
    print_warning "Skipping tests (--no-tests specified)"
    TEST_RESULT=0
fi

# Step 6: Cleanup or keep running
if [ "$KEEP_RUNNING" = true ]; then
    echo ""
    print_step "Services are still running. Use the following commands:"
    echo "  View logs:     docker compose -f $COMPOSE_FILE logs -f"
    echo "  Run tests:     docker compose -f $COMPOSE_FILE exec nginx-lcm /e2e/test-full-flow.sh"
    echo "  Shell access:  docker compose -f $COMPOSE_FILE exec nginx-lcm bash"
    echo "  Stop:          docker compose -f $COMPOSE_FILE down -v"
else
    print_step "Stopping services..."
    docker compose -f "$COMPOSE_FILE" down -v
    print_success "Services stopped and volumes cleaned"
fi

exit $TEST_RESULT
