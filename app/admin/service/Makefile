# Makefile for Admin Service

include ../../../app.mk

# Admin-specific variables
ADMIN_IMAGE_NAME ?= menta2l/admin-service
ADMIN_IMAGE_TAG ?= $(VERSION)
DOCKER_REGISTRY ?=

# Build the server binary
.PHONY: build-server
build-server: api openapi
	@echo "Building Admin server..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/admin-server ./cmd/server
	@echo "Build complete!"

# Build Docker image for Admin service
.PHONY: docker
docker:
	@echo "Building Docker image $(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG)..."
	@docker build \
		--no-cache \
		-t $(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG) \
		-t $(ADMIN_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Build Docker image with custom registry
.PHONY: docker-tag
docker-tag: docker
ifdef DOCKER_REGISTRY
	@echo "Tagging image for registry $(DOCKER_REGISTRY)..."
	@docker tag $(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG) $(DOCKER_REGISTRY)/$(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG)
	@docker tag $(ADMIN_IMAGE_NAME):latest $(DOCKER_REGISTRY)/$(ADMIN_IMAGE_NAME):latest
endif

# Push Docker image to registry
.PHONY: docker-push
docker-push: docker-tag
ifdef DOCKER_REGISTRY
	@echo "Pushing image to $(DOCKER_REGISTRY)..."
	@docker push $(DOCKER_REGISTRY)/$(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG)
	@docker push $(DOCKER_REGISTRY)/$(ADMIN_IMAGE_NAME):latest
else
	@echo "DOCKER_REGISTRY not set, skipping push"
endif

# Build multi-platform Docker image
.PHONY: docker-buildx
docker-buildx:
	@echo "Building multi-platform Docker image..."
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(ADMIN_IMAGE_NAME):$(ADMIN_IMAGE_TAG) \
		-t $(ADMIN_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Run the server locally
.PHONY: run-server
run-server:
	@go run ./cmd/server -c ./configs

# Run tests
.PHONY: test
test:
	@go test -v ./...

# Run tests with coverage
.PHONY: test-cover
test-cover:
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
.PHONY: clean
clean:
	@rm -rf ./bin
	@rm -f coverage.out coverage.html
	@echo "Clean complete!"

# Show Admin-specific help
.PHONY: admin-help
admin-help:
	@echo ""
	@echo "Admin Service Makefile"
	@echo "======================"
	@echo ""
	@echo "Build targets:"
	@echo "  build-server   Build the server binary"
	@echo "  build          Build with API and OpenAPI generation"
	@echo "  app            Full build (api, openapi, wire, ent, build)"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker         Build Docker image"
	@echo "  docker-tag     Build and tag for registry (set DOCKER_REGISTRY)"
	@echo "  docker-push    Build, tag, and push to registry"
	@echo "  docker-buildx  Build multi-platform image (amd64/arm64)"
	@echo ""
	@echo "Run targets:"
	@echo "  run            Run the server locally (with API generation)"
	@echo "  run-server     Run the server locally (without generation)"
	@echo ""
	@echo "Code generation:"
	@echo "  gen            Generate all (ent, wire, api, openapi)"
	@echo "  ent            Generate ent schema code"
	@echo "  wire           Generate wire dependency injection"
	@echo "  api            Generate protobuf API code"
	@echo "  openapi        Generate OpenAPI v3 docs"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run tests"
	@echo "  test-cover     Run tests with coverage report"
	@echo ""
	@echo "Other targets:"
	@echo "  clean          Remove build artifacts"
	@echo "  env            Show environment variables"
	@echo ""
	@echo "Variables:"
	@echo "  ADMIN_IMAGE_NAME   Docker image name (default: menta2k/admin-service)"
	@echo "  ADMIN_IMAGE_TAG    Docker image tag (default: VERSION)"
	@echo "  DOCKER_REGISTRY    Docker registry for push (optional)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-server"
	@echo "  make docker"
	@echo "  make docker-push DOCKER_REGISTRY=ghcr.io/myorg"
	@echo ""
