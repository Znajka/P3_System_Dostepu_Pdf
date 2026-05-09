# P3 System Dostępu PDF

Secure PDF access control: encrypted storage, time-bound grants, JWT-based authentication, and a browser viewer that streams decrypted content under policy (no direct file download in the secure flow).

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick start (Docker)](#quick-start-docker)
- [Local development](#local-development)
- [Configuration](#configuration)
- [Services and ports](#services-and-ports)
- [Demo accounts](#demo-accounts)
- [API documentation](#api-documentation)
- [Project layout](#project-layout)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Authentication** — JWT (access + refresh issued on login), role-based access (`ADMIN`, `USER`).
- **Documents** — PDF upload; server-side encryption (AES-256-GCM) with per-document keys (DEK) wrapped via KMS integration (Vault-oriented).
- **Sharing** — Grant / revoke access with validity windows; owners and admins manage grants.
- **Viewer** — Ticket-based streaming through Spring Boot and a FastAPI microservice; PDF.js canvas rendering with viewer-side controls (print/download restrictions configurable).
- **Audit** — Access events (upload, grant, revoke, open attempts, streams) queryable by admins.
- **Optional branding** — Static logos via `frontend/public/logo_png/` (served with the SPA).

---

## Architecture

| Layer | Responsibility |
|--------|----------------|
| **React (Vite)** | SPA: login, dashboard, grants, admin audit log, secure PDF viewer. |
| **Spring Boot** | REST API, auth, JPA/PostgreSQL, DEK wrap/unwrap, tickets, audit, proxies PDF stream to browser. |
| **FastAPI** | Encrypt uploaded blobs, decrypt & stream PDF bytes using validated tickets + headers. |
| **PostgreSQL** | Users, documents, grants, key metadata, audit log, ticket nonces. |
| **HashiCorp Vault** | KMS-style endpoint for key operations (dev setup uses Vault in dev mode). |

Encrypted PDF blobs live on shared volume (`data/encrypted-documents`) when `STORAGE_TYPE=local`.

---

## Tech stack

- **Frontend:** React 18, TypeScript, Vite 5, React Router 7, Axios, PDF.js  
- **Backend:** Java 21, Spring Boot 3.2, Spring Security, Spring Data JPA, JWT (JJWT), PostgreSQL  
- **PDF service:** Python 3.12, FastAPI, Uvicorn, Cryptography  
- **Infrastructure:** Docker Compose, PostgreSQL 16, Vault (container)

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose plugin) for the full stack  
- **Node.js** (LTS, e.g. 20+) and **npm** — only if you run the frontend outside Docker against local/backend containers  
- **Java 21 + Maven** — only if you build/run Spring Boot without Docker

---

## Quick start (Docker)

From the repository root:

1. **Data directory** (encrypted PDFs on host):

   ```bash
   mkdir -p data/encrypted-documents
   ```

2. **Optional:** copy `.env.example` to `.env` and set strong secrets for anything beyond local demos (`APP_JWT_SECRET`, `POSTGRES_PASSWORD`, etc.).

3. **Start services:**

   ```bash
   docker compose up -d --build
   ```

4. Wait until **`spring-boot-backend`** is healthy (first build can take a few minutes).

5. **Open the app:**  
   The Spring Boot image bundles the built SPA — use **[http://localhost:8080](http://localhost:8080)**.

6. **Optional — pgAdmin** (profile `dev`):

   ```bash
   docker compose --profile dev up -d
   ```

**Rebuild after frontend changes:** the UI is compiled into the Spring Boot image. Force a fresh frontend build:

```bash
docker compose build --no-cache spring-boot-backend
docker compose up -d spring-boot-backend
```

---

## Local development

### Backend stack in Docker, frontend on host (typical)

1. Start **postgres**, **vault**, **spring-boot-backend**, and **fastapi-pdf-service** with Compose (you can scale down to only the services you need, or run full `docker compose up`).

2. In **`frontend/`**:

   ```bash
   cp .env.example .env
   # Set REACT_APP_FASTAPI_URL=http://localhost:8443 for the Docker FastAPI port mapping
   npm ci
   npm run dev
   ```

3. Vite dev server defaults to **port 3000** and proxies **`/api`** to **http://localhost:8080**.

4. Open **[http://localhost:3000](http://localhost:3000)**.

### Ports (default)

See [Services and ports](#services-and-ports).

---

## Configuration

| Area | Notes |
|------|--------|
| **Root `.env`** | Optional overrides for Compose (see `.env.example`). |
| **Spring Boot** | `backend/src/main/resources/application.yml` and profile-specific files (e.g. `application-docker.yml`). Key vars are mirrored in `docker-compose.yml`. |
| **Frontend** | `frontend/.env` — `REACT_APP_SPRING_BOOT_URL`, `REACT_APP_FASTAPI_URL`, PDF.js and viewer flags (see `frontend/.env.example`). |

Never commit real secrets. Use environment variables or your platform’s secret store in production.

---

## Services and ports

| Service | Host port | Description |
|---------|-----------|-------------|
| Spring Boot + SPA | **8080** | REST API, bundled React app, `/api/stream/pdf` proxy |
| FastAPI PDF | **8443** | Encryption / streaming (HTTP in dev container) |
| PostgreSQL | **5432** | Database |
| Vault | **8200** | KMS-style dev server |
| pgAdmin | **5050** | Optional (`--profile dev`) |

---

## Demo accounts

Seeded for local/demo use (see `DevUserSeeder`): password pattern **`{username}123`** (e.g. `admin` / `admin123`).  
Includes an **ADMIN** user and several **USER** accounts (`alice`, `bob`, etc.).

---

## API documentation

With Spring Boot running, interactive OpenAPI UI is typically available at:

- **Swagger UI:** `/swagger-ui.html`  
- **OpenAPI JSON:** `/v3/api-docs`

Exact paths follow **springdoc-openapi** defaults for this project.

---

## Project layout

```text
├── backend/                 # Spring Boot application + PDF microservice
│   ├── src/                 # Java sources
│   ├── pdf-microservice/    # FastAPI app
│   ├── db/init/             # PostgreSQL init SQL
│   └── Dockerfile.springboot
├── frontend/                # React + Vite SPA
├── data/encrypted-documents # Local encrypted blobs (gitignored content)
├── docker-compose.yml
├── .env.example
└── CONTRIBUTING.md
```

---

## Security notes

- Replace all demo JWT secrets, DB passwords, and internal API keys before any production deployment.
- Vault in Compose is **development-oriented**; run a production-hardened Vault (or cloud KMS) for real workloads.
- The PDF microservice’s internal endpoints must not be exposed publicly; network isolation and service authentication are part of a secure deployment.
- Review **[CONTRIBUTING.md](CONTRIBUTING.md)** for cryptographic and logging requirements.

---

## Troubleshooting

| Issue | Suggestion |
|-------|------------|
| UI changes not visible in Docker | Rebuild **`spring-boot-backend`** without cache so `npm run build` runs again (see Quick start). Hard-refresh the browser (Ctrl+Shift+R). |
| Spring Boot not healthy | `docker compose logs spring-boot-backend` — wait for DB/Vault; check `SPRING_DATASOURCE_*`. |
| FastAPI / stream errors | Ensure **`FASTAPI_SERVICE_URL`** from Spring points at the PDF container and **`data/encrypted-documents`** is shared. |
| Maven / npm not found | Use Docker for builds, or install toolchains listed in [Prerequisites](#prerequisites). |

More setup detail may exist in **`docker.md`** or internal docs if present in the repo.

---

## Contributing

Contributions are welcome. Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for branch naming, security rules, and review expectations.

---

## License

This repository does not include a default `LICENSE` file. Add an explicit **LICENSE** (e.g. MIT, Apache-2.0) if you intend to open-source the project under clear terms.

---

## Acknowledgments

Built for controlled PDF distribution with auditability and encryption at rest. Adjust branding under `frontend/public/logo_png/` if your deployment requires custom logos.
