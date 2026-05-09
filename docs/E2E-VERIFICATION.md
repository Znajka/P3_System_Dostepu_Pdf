# End-to-end verification (manual)

Prerequisites: from repo root, run **`docker compose up --build -d`** (defaults for `POSTGRES_PASSWORD`, `APP_JWT_SECRET`, and `KMS_AUTH_TOKEN` are set for local dev).

- **First-time / schema issues:** wipe the Postgres volume once: **`docker compose down -v`** then **`docker compose up --build -d`** (runs `backend/db/init/*.sql`).
- Open the app at **http://localhost:8080** (SPA + API). FastAPI streams PDFs at **http://localhost:8443** (JWT from open-ticket).

## API

1. **Login** — `POST /api/auth/login` with `admin`/`admin123` or any user `alice`/`alice123`, `bob`/`bob123`, `carol`/`carol123`, `dave`/`dave123`. Response includes `accessToken` and `userId`.
2. **Upload** — `POST /api/documents` multipart (`title`, `file` PDF) with `Authorization: Bearer <token>`. Caller becomes document owner.
3. **Grant** — `POST /api/documents/{id}/grant` with exactly one of `granteeUserId`, `granteeUsername`, `granteeEmail`, plus `expiresAt` (future ISO-8601). Optional `validFrom` (ISO-8601): opening is allowed only when `validFrom ≤ now < expiresAt`. Omit `validFrom` to start access immediately.
4. **Open ticket** — `GET /api/documents/{id}/open-ticket` as grantee or owner; returns short-lived JWT.
5. **Encryption metadata** — `GET /api/internal/documents/{id}/encryption-metadata` with same access as viewing.
6. **Stream** — `GET /stream/{ticket}` on the PDF service with headers `X-DEK`, `X-Nonce`, `X-Tag` (base64) from metadata. Expect `200` PDF; ticket is single-use via `POST /api/internal/tickets/mark-used` (called from FastAPI).
7. **Revoke** — `POST /api/documents/{id}/revoke` with one grantee identifier, or `POST /api/grants/{grantId}/revoke` with optional JSON `{ "reason": "..." }`; ticket/metadata should fail afterward for that grantee.
8. **Status / audit** — `GET /api/documents/{id}/status` (owner sees `shareStatus` per grant: PENDING, ACTIVE, EXPIRED, REVOKED). **Admin:** `GET /api/logs/access-events`.

## UI

**Docker (recommended):** After `docker compose up --build`, open **http://localhost:8080** — React is bundled inside Spring Boot (`SpaForwardingController` + `/static`). PDF streaming still uses FastAPI at **http://localhost:8443** (set `REACT_APP_FASTAPI_URL` when building if your setup differs).

**Local dev:** `npm run dev` on port **3000** with Vite proxy to Spring (`/api`) and FastAPI (`/stream`).

## Security notes

- Plain PDF is not served directly; storage holds encrypted blobs.
- Rotate `APP_INTERNAL_API_KEY` and `APP_JWT_SECRET` outside demos; enable IP pinning only when client IP is consistent end-to-end (`APP_SECURITY_IP_PINNING_ENABLED`).
