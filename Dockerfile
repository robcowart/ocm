# Stage 1: Frontend Build
FROM --platform=$BUILDPLATFORM node:22-alpine3.23 AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Backend Build
FROM golang:1.26-alpine3.23 AS backend-builder
WORKDIR /app
RUN apk add --no-cache git gcc musl-dev sqlite-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=1 go build -o ocm ./cmd/ocm

# Stage 3: Runtime
FROM alpine:3.23
RUN apk --no-cache add ca-certificates sqlite-libs
RUN addgroup -g 2000 -S ocm && adduser -u 2000 -S ocm -G ocm
WORKDIR /app

# Copy built artifacts
COPY --from=backend-builder /app/ocm .
COPY --from=frontend-builder /app/frontend/dist ./static
COPY config.yaml .

# Create data directory
RUN mkdir -p /app/data && chown -R ocm:ocm /app/data /app

# Switch to non-root user
USER ocm

EXPOSE 8000

ENTRYPOINT ["/app/ocm"]
