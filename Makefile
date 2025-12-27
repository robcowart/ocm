.PHONY: build run test clean docker-build docker-run frontend-build frontend-dev deps

# Build the Go binary
build:
	CGO_ENABLED=1 go build -o ocm ./cmd/ocm

# Run locally (requires config.yaml)
run: build
	./ocm

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
	docker build -t ocm-cert-manager:latest .

# Run Docker container with SQLite
docker-run:
	docker run -d \
		-p 8080:8080 \
		-v ocm-data:/app/data \
		--name ocm \
		ocm-cert-manager:latest

# Build frontend only
frontend-build:
	cd frontend && npm run build

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

# Initialize database directory
init-db:
	mkdir -p data

# Development mode (run backend and frontend separately)
dev: init-db
	@echo "Run 'make run' in one terminal and 'make frontend-dev' in another"
