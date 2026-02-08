# go-tangra-portal

API gateway and administration backend for the Go-Tangra platform. Serves as a Backend-for-Frontend (BFF) with dynamic HTTP-to-gRPC transcoding, authentication, authorization, and module discovery.

## Features

- **Dynamic Module Router** — Hot-reloading of microservice routes without restart
- **HTTP/gRPC Transcoding** — REST clients transparently access gRPC services via protobuf descriptors
- **Authentication** — JWT tokens with access/refresh lifecycle, MFA support
- **Authorization** — Casbin/OPA policy engines with role-based access control
- **Multi-Tenant** — Tenant isolation at service and database levels
- **Audit Logging** — API, login, operation, and data access audit trails
- **Module Registration** — Services self-register with OpenAPI specs and menu definitions
- **File Management** — S3-compatible object storage via MinIO

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 7787 | gRPC | Service-to-service communication |
| 7788 | HTTP | REST API for frontend |
| 7789 | HTTP | Server-Sent Events (SSE) |

## Core Services

| Domain | Purpose |
|--------|---------|
| **Authentication** | Login, token management, OAuth grant types, MFA |
| **User Management** | User CRUD, roles, permissions, positions |
| **Admin Portal** | Dashboard, menus, module registration, statistics |
| **Permissions** | RBAC, permission groups, data scope enforcement |
| **File Transfer** | Upload/download with MinIO backend |
| **Audit** | API, login, operation, and data access logs |
| **Tasks** | Background job scheduling |
| **Internal Messages** | System notifications and categories |
| **Dictionaries** | System dictionaries and localization |

## Module Registration

Services register dynamically at startup, providing:
- gRPC endpoint address
- OpenAPI specification
- Protobuf descriptors
- UI menu definitions
- Periodic heartbeat for health tracking

Registered modules: LCM, Deployer, IPAM, Warden, Paperless

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
    └── Paperless Service (:9500)
```

## Configuration

Service configs in `app/admin/service/configs/`:
- `server.yaml` — HTTP/gRPC server ports, TLS, timeouts
- `auth.yaml` — JWT settings, authentication engines
- `data.yaml` — Database connection (PostgreSQL, MySQL, SQLite)
- `oss.yaml` — MinIO/S3 object storage

Supports config sources: local YAML, Consul, etcd, Nacos, Kubernetes ConfigMaps.

## Build

```bash
make api            # Generate gRPC/HTTP code from protos
make openapi        # Generate OpenAPI documentation
make ent            # Generate Ent ORM code
make wire           # Generate dependency injection
make build          # Build binary
make docker         # Build Docker image
make test           # Run tests
```

## Docker

Multi-stage build with Alpine runtime. Runs as non-root user.

## Deployment

Deployment scripts in `script/`:
- `prepare_*.sh` — OS environment setup (CentOS, Rocky, Ubuntu)
- `docker_compose_install.sh` — Full Docker deployment
- `build_install.sh` — Build binaries + PM2 process management

## Dependencies

- **Framework**: Kratos v2
- **ORM**: Ent + GORM
- **Auth**: JWT, Casbin/OPA
- **Storage**: MinIO
- **Database**: PostgreSQL, MySQL, SQLite
- **Cache**: Redis
- **Protobuf**: Buf (128 proto files)
