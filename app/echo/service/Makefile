.PHONY: all build run clean proto docker

SERVICE_NAME := echo-service
VERSION := 1.0.0
BUILD_DIR := bin

all: build

# Build the service
build:
	@echo "Building $(SERVICE_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(SERVICE_NAME) ./cmd/server

# Run the service locally
run: build
	@echo "Running $(SERVICE_NAME)..."
	./$(BUILD_DIR)/$(SERVICE_NAME)

# Run with specific config
run-dev:
	@echo "Running $(SERVICE_NAME) in development mode..."
	GRPC_ADDR=0.0.0.0:9500 \
	ADMIN_GRPC_ENDPOINT=localhost:9000 \
	OPENAPI_PATH=configs/openapi.yaml \
	go run ./cmd/server

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)

# Generate proto files (assumes proto files exist in api/protos/echo)
proto:
	@echo "Generating proto files..."
	cd ../../../ && make api-echo

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(SERVICE_NAME):$(VERSION) .

# Run in Docker
docker-run:
	@echo "Running in Docker..."
	docker run -p 9500:9500 \
		-e GRPC_ADDR=0.0.0.0:9500 \
		-e ADMIN_GRPC_ENDPOINT=admin-service:9000 \
		$(SERVICE_NAME):$(VERSION)

# Generate proto descriptor set for dynamic registration
proto-descriptor:
	@echo "Generating proto descriptor set..."
	protoc --descriptor_set_out=configs/echo.pb \
		--include_imports \
		-I ../../../api/protos \
		-I $(GOPATH)/pkg/mod/github.com/googleapis/googleapis@v0.0.0-20240102182953-50ed04b92917 \
		../../../api/protos/echo/service/v1/echo.proto

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the service binary"
	@echo "  run            - Build and run the service"
	@echo "  run-dev        - Run in development mode with go run"
	@echo "  clean          - Remove build artifacts"
	@echo "  proto          - Generate proto files"
	@echo "  proto-descriptor - Generate proto descriptor set"
	@echo "  docker         - Build Docker image"
	@echo "  docker-run     - Run in Docker container"
