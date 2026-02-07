# Makefile for Paperless Service

include ../../../app.mk

# Paperless-specific variables
PAPERLESS_IMAGE_NAME ?= menta2l/paperless-service
PAPERLESS_IMAGE_TAG ?= $(VERSION)
DOCKER_REGISTRY ?=

# Build the server binary
.PHONY: build-server
build-server:
	@echo "Building Paperless server..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/paperless-server ./cmd/server

# Build Docker image for Paperless service
.PHONY: docker
docker:
	@echo "Building Docker image $(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG)..."
	@docker build \
		-t $(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG) \
		-t $(PAPERLESS_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Build Docker image with custom registry
.PHONY: docker-tag
docker-tag: docker
ifdef DOCKER_REGISTRY
	@echo "Tagging image for registry $(DOCKER_REGISTRY)..."
	@docker tag $(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG) $(DOCKER_REGISTRY)/$(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG)
	@docker tag $(PAPERLESS_IMAGE_NAME):latest $(DOCKER_REGISTRY)/$(PAPERLESS_IMAGE_NAME):latest
endif

# Push Docker image to registry
.PHONY: docker-push
docker-push: docker-tag
ifdef DOCKER_REGISTRY
	@echo "Pushing image to $(DOCKER_REGISTRY)..."
	@docker push $(DOCKER_REGISTRY)/$(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG)
	@docker push $(DOCKER_REGISTRY)/$(PAPERLESS_IMAGE_NAME):latest
else
	@echo "Pushing image to Docker Hub..."
	@docker push $(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG)
	@docker push $(PAPERLESS_IMAGE_NAME):latest
endif

# Build multi-platform Docker image
.PHONY: docker-buildx
docker-buildx:
	@echo "Building multi-platform Docker image..."
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(PAPERLESS_IMAGE_NAME):$(PAPERLESS_IMAGE_TAG) \
		-t $(PAPERLESS_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		../../../

# Run the server locally
.PHONY: run-server
run-server:
	@go run ./cmd/server -c ./configs

# Generate ent schema
.PHONY: ent
ent:
ifneq ("$(wildcard ./internal/data/ent)","")
	@ent generate \
		--feature sql/modifier \
		--feature sql/upsert \
		--feature sql/lock \
		./internal/data/ent/schema
endif

# Generate wire dependencies
.PHONY: wire
wire:
	@cd ./cmd/server && wire

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

# Generate all (ent + wire + proto)
.PHONY: generate
generate: ent wire
	@echo "Generation complete!"
