# Open Certificate Manager (OCM)

A secure, containerized PKI certificate management system for creating and managing SSL/TLS certificates with a modern web interface.

## Features

- **Secure Certificate Management**: Generate and manage X.509 certificates with industry-standard encryption
- **Multiple Root CAs**: Support for multiple Certificate Authorities with hierarchical trust models
- **Modern Web UI**: Built with React, TypeScript, and Shadcn UI for an intuitive user experience
- **Secure Key Storage**: AES-256-GCM encryption for private keys at rest
- **Multiple Export Formats**: Export certificates as PEM bundles or PKCS#12/PFX
- **Flexible Database**: Support for both SQLite (embedded) and PostgreSQL
- **Docker Support**: Runs in a single container for easy deployment
- **Authentication**: JWT-based authentication with bcrypt password hashing
- **Comprehensive Logging**: Structured logging with Zap

## Quick Start

### Using Docker Compose (Recommended)

#### SQLite (Single Container)

```bash
# Build and start the service
docker-compose up -d ocm-sqlite

# Access the web interface
open http://localhost:8080
```

#### PostgreSQL

```bash
# Build and start the service with PostgreSQL
docker-compose up -d ocm-postgres postgres

# Access the web interface
open http://localhost:8081
```

### Using Docker Manually

```bash
# Build the image
docker build -t ocm-cert-manager:latest .

# Run with SQLite
docker run -d \
  -p 8080:8080 \
  -v ocm-data:/app/data \
  --name ocm \
  ocm-cert-manager:latest
```

### Local Development

#### Prerequisites

- Go 1.22 or higher
- Node.js 20 or higher
- Make (optional, for convenience commands)

#### Backend Setup

```bash
# Install Go dependencies
go mod download

# Create data directory
mkdir -p data

# Run the backend
go run ./cmd/server
```

#### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

The frontend dev server will proxy API requests to the backend at `http://localhost:8080`.

## First-Time Setup

1. **Initial Access**: Navigate to `http://localhost:8080`
2. **Setup Wizard**: On first run, you'll be guided through initial setup
3. **Create Admin Account**: Choose a username and strong password
4. **Master Key**: The system will generate a master encryption key
   - **CRITICAL**: Save this key securely! It encrypts all private keys in the database
   - If lost, you cannot decrypt your certificates
5. **Complete Setup**: You'll be automatically logged in to the dashboard

## Usage

### Creating a Certificate Authority

1. Navigate to **Certificate Authorities**
2. Click **Create Root CA**
3. Fill in the details:
   - **Friendly Name**: A name for easy identification
   - **Common Name**: The CA's common name (e.g., "My Organization Root CA")
   - **Organization**: Your organization name
   - **Country**: Two-letter country code (e.g., "US")
4. Click **Create**

The CA will be generated with:

- RSA 2048-bit key (default)
- 10-year validity period
- Self-signed certificate

### Creating a Certificate

1. Navigate to **Certificates**
2. Click **Create Certificate**
3. Select the **Certificate Authority** to sign the certificate
4. Enter the **Common Name** (e.g., `example.com`)
5. Add **Subject Alternative Names** (optional):
   - DNS names: `www.example.com`, `*.example.com`
   - IP addresses: 192.168.1.1
6. Click **Create**

The certificate will be generated with:

- Same algorithm as the CA
- 1-year validity period
- Server authentication enabled

### Exporting Certificates

From the Certificates page:

1. Find your certificate
2. Click **Export PEM** for:
   - Linux/Unix systems (Nginx, Apache, HAProxy)
   - Includes certificate, CA chain, and private key
3. Click **Export PFX** for:
   - Windows systems
   - Java applications (Tomcat, Java KeyStore)
   - Password-protected PKCS#12 format

## Configuration

The application is configured via `config.yaml`:

```yaml
server:
  port: 8080                    # HTTP server port
  host: 0.0.0.0                # Bind address
  read_timeout: 30s
  write_timeout: 30s
  tls_enabled: false           # Enable HTTPS (requires cert/key)

database:
  type: sqlite                  # sqlite or postgres
  sqlite:
    path: ./data/ocm.db
  postgres:
    host: localhost
    port: 5432
    database: ocm
    user: ocm
    password: ""
    ssl_mode: disable

jwt:
  secret: ""                    # Auto-generated on first run
  expiration: 24h
  issuer: ocm-cert-manager

crypto:
  default_ca_validity: 87600h   # 10 years
  default_cert_validity: 8760h  # 1 year
  default_algorithm: rsa        # rsa or ecdsa
  default_rsa_bits: 2048        # 2048 or 4096
  default_ec_curve: P256        # P256 or P384

logging:
  level: info                   # debug, info, warn, error
  format: json                  # json or console
  output: stdout

security:
  cors_enabled: true
  cors_origins:
    - http://localhost:3000
    - http://localhost:8080
  rate_limit_enabled: true
  rate_limit_requests: 100
  rate_limit_window: 1m
```

### Environment Variable Overrides

Configuration can be overridden with environment variables:

```bash
OCM_SERVER_PORT=9000
OCM_DB_TYPE=postgres
OCM_DB_POSTGRES_HOST=db.example.com
OCM_DB_POSTGRES_PASSWORD=secure_password
OCM_LOG_LEVEL=debug
```

## Security Best Practices

### Master Key Management

- **Backup Immediately**: Save the master key displayed during setup
- **Secure Storage**: Store in a password manager or secure vault
- **Never Commit**: Do not commit the master key to version control
- **Disaster Recovery**: Keep an offline backup in a secure location

### Password Requirements

- Minimum 8 characters
- Must contain at least one letter
- Must contain at least one number

### Network Security

- **Use HTTPS in Production**: Enable TLS in the configuration
- **Firewall Rules**: Restrict access to trusted networks
- **Reverse Proxy**: Consider using Nginx or Traefik with SSL termination
- **Regular Updates**: Keep the application and dependencies updated

### Database Security

- **SQLite**: Secure the database file with appropriate file permissions
- **PostgreSQL**: Use strong passwords and SSL connections
- **Backups**: Regularly backup both the database and master key

## API Endpoints

The application exposes a RESTful API:

### Setup

- `GET /api/v1/setup/status` - Check if setup is complete
- `POST /api/v1/setup` - Perform initial setup

### Authentication

- `POST /api/v1/auth/login` - Login and get JWT token
- `GET /api/v1/auth/me` - Get current user info (authenticated)

### Certificate Authorities

- `GET /api/v1/authorities` - List all CAs
- `GET /api/v1/authorities/:id` - Get specific CA
- `POST /api/v1/authorities` - Create Root CA
- `POST /api/v1/authorities/import` - Import existing CA

### Certificates

- `GET /api/v1/certificates` - List all certificates
- `GET /api/v1/certificates/:id` - Get specific certificate
- `POST /api/v1/certificates` - Create certificate
- `POST /api/v1/certificates/:id/export` - Export certificate
- `PUT /api/v1/certificates/:id/revoke` - Revoke certificate

All authenticated endpoints require `Authorization: Bearer <token>` header.

## Building from Source

### Backend

```bash
# Build binary
go build -o ocm ./cmd/ocm

# Run
./ocm
```

### Frontend

```bash
cd frontend

# Build production assets
npm run build

# Output in frontend/dist/
```

### Docker Image

```bash
# Build
docker build -t ocm-cert-manager:latest .

# Run
docker run -p 8080:8080 -v ocm-data:/app/data ocm-cert-manager:latest
```

## Makefile Commands

```bash
make build           # Build Go binary
make run             # Run locally
make test            # Run tests
make clean           # Clean build artifacts
make docker-build    # Build Docker image
make docker-run      # Run Docker container (SQLite)
make frontend-build  # Build frontend only
make frontend-dev    # Run frontend dev server
```

## Troubleshooting

### Setup Wizard Not Appearing

Check that no users exist in the database:

```bash
# SQLite
sqlite3 data/ocm.db "SELECT COUNT(*) FROM users;"

# If users exist but you need to reset
rm data/ocm.db
```

### Cannot Login

- Verify credentials are correct
- Check logs for authentication errors
- Ensure JWT secret is properly configured

### Database Connection Errors

**PostgreSQL:**

- Verify connection settings in config.yaml
- Ensure PostgreSQL is running and accessible
- Check firewall rules

**SQLite:**

- Verify the data directory exists and is writable
- Check file permissions

### Frontend Not Loading

- Ensure frontend was built: `cd frontend && npm run build`
- Check that static files are in `./static/` directory
- Verify the backend is serving static files correctly

### Certificate Export Fails

- Verify the certificate exists
- Check that the master key is correctly configured
- Review logs for encryption errors

## Technology Stack

**Backend:**

- Go 1.22
- Gin (HTTP framework)
- Zap (structured logging)
- crypto/x509 (PKI operations)
- AES-256-GCM (key encryption)
- JWT (authentication)
- SQLite / PostgreSQL (database)

**Frontend:**

- React 18
- TypeScript 5
- Vite (build tool)
- Shadcn UI (component library)
- TanStack Query (data fetching)
- React Router (routing)
- Tailwind CSS (styling)

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Roadmap

Future enhancements planned:

- Intermediate CAs (3-tier hierarchy)
- Certificate Revocation Lists (CRL)
- Full RBAC with granular permissions
- Certificate renewal workflows
- ACME protocol support
- HSM integration
- Audit logging
- Webhook notifications
- Certificate templates
- Bulk operations

---

**⚠️ Security Notice**: This application manages cryptographic material and should be deployed in a secure environment. Always use HTTPS in production, secure your master key, and follow security best practices.
