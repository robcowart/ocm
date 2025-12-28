.PHONY: build test clean docker-build frontend-build frontend-dev frontend-deps deps build-all release release-local buildx-setup

# Build the Go binary
build:
	CGO_ENABLED=1 go build -o ocm ./cmd/ocm

# Build everything (frontend + backend)
build-all: frontend-build build docker-build

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f ocm
	rm -rf frontend/dist
	rm -rf data/*.db

# Build Docker image
docker-build:
	docker build -t ocm:latest .

# Build frontend only
frontend-build:
	cd frontend && npm run build
	rm -rf static
	mkdir -p static
	cp -r frontend/dist/* static/

# Run frontend dev server
frontend-dev:
	cd frontend && npm run dev

# Install Go dependencies
deps:
	go mod download
	go mod tidy

# Install frontend dependencies
frontend-deps:
	cd frontend && npm install

# Setup Docker Buildx for multi-platform builds
buildx-setup:
	@echo "Setting up Docker Buildx..."
	@if ! docker buildx ls | grep -q ocm-builder; then \
		echo "Creating new builder instance..."; \
		docker buildx create --name ocm-builder --use --platform linux/amd64,linux/arm64; \
	else \
		echo "Builder instance already exists, using it..."; \
		docker buildx use ocm-builder; \
	fi
	@docker buildx inspect --bootstrap
	@echo "Buildx setup complete!"

# Build multi-architecture Docker images for release (creates manifest, ready to push)
release: buildx-setup frontend-build
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make release VERSION=1.0.0"; \
		exit 1; \
	fi
	@echo "Building multi-architecture release $(VERSION) for linux/amd64 and linux/arm64..."
	@echo "Note: Multi-arch builds cannot be loaded locally. Building to cache only."
	@echo ""
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--tag ocm:$(VERSION) \
		--tag ocm:latest \
		.
	@echo ""
	@echo "✓ Multi-architecture build complete!"
	@echo ""
	@echo "To push to Docker Hub (recommended for multi-arch):"
	@echo "  docker buildx build --platform linux/amd64,linux/arm64 \\"
	@echo "    --tag <your-username>/ocm:$(VERSION) \\"
	@echo "    --tag <your-username>/ocm:latest \\"
	@echo "    --push ."
	@echo ""
	@echo "To load a specific architecture locally:"
	@echo "  make release-local VERSION=$(VERSION) ARCH=amd64"
	@echo "  make release-local VERSION=$(VERSION) ARCH=arm64"

# Build and load single-architecture image locally
release-local: buildx-setup frontend-build
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make release-local VERSION=1.0.0 ARCH=amd64"; \
		exit 1; \
	fi
	@ARCH=$${ARCH:-amd64}; \
	echo "Building and loading linux/$$ARCH image..."; \
	docker buildx build \
		--platform linux/$$ARCH \
		--tag ocm:$(VERSION)-$$ARCH \
		--tag ocm:latest \
		--load \
		.
	@echo ""
	@echo "✓ Image loaded locally as ocm:$(VERSION)-$${ARCH:-amd64} and ocm:latest"

