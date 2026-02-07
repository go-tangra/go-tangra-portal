# Makefile for LCM Service

include ../../../app.mk

# LCM-specific variables
LCM_IMAGE_NAME ?= menta2l/lcm-service
LCM_IMAGE_TAG ?= $(VERSION)
DOCKER_REGISTRY ?=

# Build both server and client binaries
.PHONY: build-all
build-all: api
	@echo "Building LCM server..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/lcm-server ./cmd/server
	@echo "Building LCM client..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/lcm-client ./cmd/client
	@echo "Build complete!"

# Build only the server
.PHONY: build-server
build-server:
	@echo "Building LCM server..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/lcm-server ./cmd/server

# Build only the client
.PHONY: build-client
build-client:
	@echo "Building LCM client..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/lcm-client ./cmd/client

# Build Docker image for LCM service
.PHONY: docker
docker:
	@echo "Building Docker image $(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG)..."
	@docker build \
		-t $(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG) \
		-t $(LCM_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Build Docker image with custom registry
.PHONY: docker-tag
docker-tag: docker
ifdef DOCKER_REGISTRY
	@echo "Tagging image for registry $(DOCKER_REGISTRY)..."
	@docker tag $(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG) $(DOCKER_REGISTRY)/$(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG)
	@docker tag $(LCM_IMAGE_NAME):latest $(DOCKER_REGISTRY)/$(LCM_IMAGE_NAME):latest
endif

# Push Docker image to registry
.PHONY: docker-push
docker-push: docker-tag
ifdef DOCKER_REGISTRY
	@echo "Pushing image to $(DOCKER_REGISTRY)..."
	@docker push $(DOCKER_REGISTRY)/$(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG)
	@docker push $(DOCKER_REGISTRY)/$(LCM_IMAGE_NAME):latest
else
	@echo "Pushing image to Docker Hub..."
	@docker push $(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG)
	@docker push $(LCM_IMAGE_NAME):latest
endif

# Build multi-platform Docker image
.PHONY: docker-buildx
docker-buildx:
	@echo "Building multi-platform Docker image..."
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(LCM_IMAGE_NAME):$(LCM_IMAGE_TAG) \
		-t $(LCM_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Run the server locally
.PHONY: run-server
run-server:
	@go run ./cmd/server -c ./configs

# Run the client locally (example)
.PHONY: run-client
run-client:
	@go run ./cmd/client --help

# Generate ent schema (override from app.mk to remove privacy feature)
.PHONY: ent
ent:
ifneq ("$(wildcard ./internal/data/ent)","")
	@ent generate \
		--feature sql/modifier \
		--feature sql/upsert \
		--feature sql/lock \
		./internal/data/ent/schema
endif

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

# Show LCM-specific help
.PHONY: lcm-help
lcm-help:
	@echo ""
	@echo "LCM Service Makefile"
	@echo "===================="
	@echo ""
	@echo "Build targets:"
	@echo "  build-all      Build both server and client binaries"
	@echo "  build-server   Build only the server binary"
	@echo "  build-client   Build only the client binary"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker         Build Docker image"
	@echo "  docker-tag     Build and tag for registry (set DOCKER_REGISTRY)"
	@echo "  docker-push    Build, tag, and push to registry"
	@echo "  docker-buildx  Build multi-platform image (amd64/arm64)"
	@echo ""
	@echo "Run targets:"
	@echo "  run-server     Run the server locally"
	@echo "  run-client     Show client help"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run tests"
	@echo "  test-cover     Run tests with coverage report"
	@echo ""
	@echo "Other targets:"
	@echo "  ent            Generate ent schema code"
	@echo "  wire           Generate wire dependency injection"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  LCM_IMAGE_NAME   Docker image name (default: menta2k/lcm-service)"
	@echo "  LCM_IMAGE_TAG    Docker image tag (default: VERSION)"
	@echo "  DOCKER_REGISTRY  Docker registry for push (optional)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-all"
	@echo "  make docker"
	@echo "  make docker-push DOCKER_REGISTRY=ghcr.io/myorg"
	@echo ""
