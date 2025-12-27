# Stage 1: Frontend Build
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Backend Build
FROM golang:1.22-alpine AS backend-builder
WORKDIR /app
RUN apk add --no-cache git gcc musl-dev sqlite-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=1 GOOS=linux go build -o ocm ./cmd/ocm

# Stage 3: Runtime
FROM alpine:latest
RUN apk --no-cache add ca-certificates sqlite-libs
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app

# Copy built artifacts
COPY --from=backend-builder /app/ocm .
COPY --from=frontend-builder /app/frontend/dist ./static
COPY config.yaml .

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data /app

# Switch to non-root user
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/ocm"]
