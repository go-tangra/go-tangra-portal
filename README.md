# go-tangra-portal

API gateway and administration backend for the Go-Tangra platform. Serves as a Backend-for-Frontend (BFF) with dynamic HTTP-to-gRPC transcoding, authentication, authorization, and module discovery.

## Features

- **Dynamic Module Router** — Hot-reloading of microservice routes without restart
- **HTTP/gRPC Transcoding** — REST clients transparently access gRPC services via protobuf descriptors
- **Authentication** — JWT tokens with access/refresh lifecycle, OAuth 2.0, MFA (TOTP, WebAuthn, SMS, backup codes)
- **Authorization** — Casbin, OPA, and Zanzibar policy engines with role-based access control
- **Multi-Tenant** — Tenant isolation at service and database levels
- **Audit Logging** — API, login, operation, data access, permission, and policy evaluation audit trails with ECDSA tamper-proof signatures
- **Module Registration** — Services self-register with OpenAPI specs, proto descriptors, and menu definitions
- **File Management** — S3-compatible object storage via MinIO
- **Internal Messaging** — System notifications with real-time SSE delivery
- **Platform Statistics** — Aggregated dashboard metrics from all registered modules
- **Task Scheduling** — Cron-based background job processing via Asynq
- **Sensitive Data Redaction** — Automatic redaction of sensitive fields in logs and responses

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 7787 | gRPC | Service-to-service communication |
| 7788 | HTTP | REST API for frontend |
| 7789 | HTTP | Server-Sent Events (SSE) |

## Architecture

```
Frontend (Vue.js)
    │
    ▼
Admin Gateway (this service)
    │ REST → gRPC transcoding
    ├── LCM Service (:9100)
    ├── Deployer Service (:9200)
    ├── Warden Service (:9300)
    ├── IPAM Service (:9400)
    ├── Paperless Service (:9500)
    ├── Sharing Service (:9600)
    └── Bookmark Service (:9700)
```

## Core Services

### Authentication & Security

| Service | Purpose |
|---------|---------|
| **AuthenticationService** | Login, logout, token refresh, WhoAmI, OAuth 2.0 providers |
| **MFAService** | Multi-factor authentication: TOTP enrollment/verification, WebAuthn/FIDO2, SMS, backup codes, device revocation |
| **LoginPolicyService** | Login policy management and enforcement |

### User & Tenant Management

| Service | Purpose |
|---------|---------|
| **UserService** | User CRUD, password management, status lifecycle (normal, disabled, pending, locked, expired, closed) |
| **UserProfileService** | Profile management, avatar upload, contact binding with verification |
| **TenantService** | Multi-tenant management, tenant creation with admin user provisioning |

### Role & Permission Management

| Service | Purpose |
|---------|---------|
| **RoleService** | Role CRUD with tenant-scoped metadata |
| **PermissionService** | Permission CRUD, permission sync from code annotations |
| **PermissionGroupService** | Permission group organization |
| **MenuService** | Menu/route tree management |
| **ApiService** | API resource tracking, route discovery, sync |

### Organization Structure

| Service | Purpose |
|---------|---------|
| **OrgUnitService** | Hierarchical organization unit management |
| **PositionService** | Position/job title management |

### Audit Logging

| Service | Purpose |
|---------|---------|
| **ApiAuditLogService** | API call audit logs (including transcoded module requests) |
| **LoginAuditLogService** | Login attempt logs with IP, device info, geo-location |
| **OperationAuditLogService** | User operation audit logs |
| **DataAccessAuditLogService** | Data access tracking |
| **PermissionAuditLogService** | Permission change audit logs |
| **PolicyEvaluationLogService** | Authorization policy evaluation decision logs |

All audit logs include ECDSA digital signatures for tamper-proofing, device fingerprinting, and sensitive data redaction.

### Content & Communication

| Service | Purpose |
|---------|---------|
| **FileService** | File metadata management |
| **FileTransferService** | Upload/download with S3 streaming |
| **UEditorService** | Rich text editor backend integration |
| **InternalMessageService** | Message send/revoke with real-time SSE delivery |
| **InternalMessageCategoryService** | Message category management |
| **InternalMessageRecipientService** | User inbox with read/unread tracking |

### Platform Services

| Service | Purpose |
|---------|---------|
| **AdminPortalService** | Initial context, navigation routes, permission codes |
| **ModuleRegistrationService** | Dynamic module lifecycle, heartbeat, discovery |
| **PlatformStatisticsService** | Aggregated stats from all modules (users, tenants, roles, integrations) |
| **TaskService** | Scheduled task management with start/stop/restart controls |
| **DictTypeService** | Dictionary type management |
| **DictEntryService** | Dictionary entry management with i18n |
| **LanguageService** | Language/locale management |

## Multi-Factor Authentication (MFA)

Supports multiple MFA methods with enrollment and challenge flows:

- **TOTP** — Time-based one-time passwords with QR code generation
- **WebAuthn/FIDO2** — Hardware security keys and biometric authenticators
- **SMS** — SMS-based verification codes
- **Backup codes** — One-time recovery codes

Endpoints:
- `POST /admin/v1/mfa/challenge` — Start MFA challenge during login (unauthenticated)
- `POST /admin/v1/mfa/verify` — Verify MFA challenge, returns JWT on success (unauthenticated)
- `GET /admin/v1/me/mfa/status` — Get current user's MFA status
- `GET /admin/v1/me/mfa/methods` — List enrolled MFA methods
- `POST /admin/v1/me/mfa/enroll` — Start enrolling an MFA method
- `POST /admin/v1/me/mfa/enroll/confirm` — Confirm enrollment with verification code
- `POST /admin/v1/me/mfa/disable` — Disable MFA
- `POST /admin/v1/me/mfa/backup-codes` — Generate new backup codes
- `GET /admin/v1/me/mfa/backup-codes` — List backup code metadata
- `DELETE /admin/v1/me/mfa/devices/{credential_id}` — Revoke a specific MFA device

## Module Registration

Services register dynamically at startup, providing:
- gRPC endpoint address
- Protobuf `FileDescriptorSet` (with `google.api.http` annotations)
- OpenAPI specification
- UI menu definitions (YAML)
- Periodic heartbeat for health tracking (30s interval)

The gateway parses proto descriptors to create HTTP routes at `/admin/v1/modules/{module_id}/v1/...`, transcoding REST requests to gRPC calls with auth context injection (`x-md-global-*` metadata).

Registered modules: LCM, Deployer, IPAM, Warden, Paperless, Sharing, Bookmark

## Authorization Engines

Multiple pluggable authorization backends:

| Engine | Description |
|--------|-------------|
| **Casbin** | RBAC/ABAC policy engine with adapter-based storage |
| **OPA** | Open Policy Agent with Rego policies (see `assets/rbac.rego`) |
| **Zanzibar** | Google Zanzibar-style ReBAC via Keto or OpenFGA |
| **noop** | No-op engine for development/testing |

## Database Schema

40 Ent ORM entities with shared mixins for auto-increment IDs, timestamps, operator tracking, tenant scoping, and soft deletes:

**Core**: User, Tenant, Role, Permission, Menu, Api, Module
**Relations**: UserRole, UserPosition, UserOrgUnit, RolePermission, PermissionMenu, PermissionApi, Membership, MembershipRole, MembershipPosition, MembershipOrgUnit
**Organization**: OrgUnit, Position
**Security**: UserCredential, LoginPolicy, PermissionPolicy, PermissionGroup, RoleMetadata
**Audit**: ApiAuditLog, LoginAuditLog, OperationAuditLog, DataAccessAuditLog, PermissionAuditLog, PolicyEvaluationLog
**Content**: File, InternalMessage, InternalMessageCategory, InternalMessageRecipient
**Dictionary**: DictType, DictEntry, DictTypeI18n, DictEntryI18n, Language
**Tasks**: Task

## Configuration

Service configs in `app/admin/service/configs/`:

| File | Purpose |
|------|---------|
| `server.yaml` | HTTP/gRPC/SSE server ports, TLS, timeouts, middleware (logging, recovery, tracing, validation, circuit breaker) |
| `auth.yaml` | JWT settings (HS256/RS256/ES256/Ed25519), WebAuthn config, authorization engine selection |
| `data.yaml` | Database connection (PostgreSQL, MySQL, SQLite), auto-migration, connection pooling, Redis |
| `oss.yaml` | MinIO/S3 object storage |
| `client.yaml` | External service clients (LCM, Deployer, Paperless, IPAM) |
| `logger.yaml` | Structured logging configuration |

Supports config sources: local YAML, Consul, etcd, Nacos, Kubernetes ConfigMaps.

## Build

```bash
make api            # Generate gRPC/HTTP code from protos (buf)
make openapi        # Generate OpenAPI v3 documentation
make ent            # Generate Ent ORM code
make wire           # Generate Wire dependency injection
make gen            # Generate all (ent + wire + api + openapi)
make build          # Build binary (with API generation)
make build_only     # Build binary (without generation)
make test           # Run tests
make test-cover     # Run tests with coverage report
make lint           # Run golangci-lint
make docker         # Build Docker image
make docker-push    # Build, tag, and push to registry
make docker-buildx  # Build multi-platform image (amd64/arm64)
make run-server     # Run the server locally
```

### Protoc Plugins

```bash
make init           # Install all protoc plugins and CLI tools
```

Plugins: `protoc-gen-go`, `protoc-gen-go-grpc`, `protoc-gen-go-http`, `protoc-gen-go-errors`, `protoc-gen-openapi`, `protoc-gen-validate`, `protoc-gen-redact`, `protoc-gen-typescript-http`

## Docker

Multi-stage build with Alpine runtime. Runs as non-root user (`appuser`).

```bash
# Build with custom registry
make docker-push DOCKER_REGISTRY=ghcr.io/myorg

# Multi-platform build
make docker-buildx
```

## Deployment

Deployment scripts in `script/`:

| Script | Purpose |
|--------|---------|
| `prepare_centos.sh` | CentOS environment setup |
| `prepare_rocky.sh` | Rocky Linux environment setup |
| `prepare_ubuntu.sh` | Ubuntu environment setup |
| `prepare_macos.sh` | macOS environment setup |
| `prepare_windows.ps1` | Windows environment setup |
| `install_golang.sh` | Go installation |
| `docker_compose_install.sh` | Full Docker Compose deployment |
| `docker_compose_install_depends.sh` | Dependencies-only deployment |
| `build_install.sh` | Build binaries + PM2 process management |

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yaml`) for Docker image build and push to GHCR.

## Testing

- Unit tests across service, data, and business logic layers
- E2E test suite in `e2e/` with dedicated Docker Compose configuration
- OPA policy tests (`assets/rbac_test.rego`)

## Dependencies

| Layer | Technology |
|-------|------------|
| **Framework** | Kratos v2 + Bootstrap |
| **ORM** | Ent |
| **Auth** | JWT (multiple algorithms), Casbin, OPA, Zanzibar |
| **Storage** | MinIO (S3-compatible) |
| **Database** | PostgreSQL, MySQL, SQLite |
| **Cache** | Redis |
| **Task Queue** | Asynq (Redis-backed) |
| **Protobuf** | Buf (31 proto files) |
| **DI** | Google Wire |
| **SSE** | Server-Sent Events for real-time notifications |

## Registered Modules

| Module | Port | Repository | Description |
|--------|------|------------|-------------|
| **LCM** | 9100 | `go-tangra-lcm` | Certificate lifecycle manager — internal CA for the service mesh, automated certificate issuance/renewal, ACME protocol support, and mTLS bootstrap for all modules |
| **Deployer** | 9200 | `go-tangra-deployer` | Deployment job management — orchestrates application deployments, tracks job status and history, rollback support |
| **Warden** | 9300 | `go-tangra-warden` | Secrets management — HashiCorp Vault backend for storing and retrieving secrets, credential rotation, secure key/value storage |
| **IPAM** | 9400 | `go-tangra-ipam` | IP address management — tracks IP allocations, subnets, VLANs, and network resource inventory across tenants |
| **Paperless** | 9500 | `go-tangra-paperless` | Document management — S3-compatible storage with Apache Tika for content extraction, Gotenberg for PDF conversion, full-text search |
| **Sharing** | 9600 | `go-tangra-sharing` | Secure file and secret sharing — generates time-limited, password-protected links for sharing files and secrets via email |
| **Bookmark** | 9700 | `rust-tangra-bookmark` | URL bookmark management — Rust-based service with Google Zanzibar-style permissions (Owner/Editor/Viewer/Sharer relations) |

## TODO

- [ ] **SSE notifications & internal messaging** — Wire up Server-Sent Events for real-time delivery of internal messages, read receipts, and system notifications to connected clients
- [ ] **Dashboard refactoring** — Redesign the platform statistics dashboard with improved layout, real-time metric widgets, and per-module health/status panels
- [ ] **External notifications** — Add notification channels for email (SMTP), Slack (webhooks/API), and SMS (provider-agnostic) with configurable routing rules and templates
