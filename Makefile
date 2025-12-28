.PHONY: build test clean docker-build frontend-build frontend-dev frontend-deps deps build-all

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
