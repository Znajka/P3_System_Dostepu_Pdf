# End-to-end verification (manual)

Prerequisites: Docker Compose with `APP_JWT_SECRET`, `APP_INTERNAL_API_KEY` (default in `docker-compose.yml` for dev), Postgres init schema applied, Vault optional for DEK mock.

## API

1. **Login** — `POST /api/auth/login` with `admin`/`admin123` or `user1`/`user123`. Response includes `accessToken` and `userId`.
2. **Upload** — `POST /api/documents` multipart (`title`, `file` PDF) with `Authorization: Bearer <token>`. Caller becomes document owner.
3. **Grant** — `POST /api/documents/{id}/grant` with exactly one of `granteeUserId`, `granteeUsername`, `granteeEmail`, plus `expiresAt` (future ISO-8601).
4. **Open ticket** — `GET /api/documents/{id}/open-ticket` as grantee or owner; returns short-lived JWT.
5. **Encryption metadata** — `GET /api/internal/documents/{id}/encryption-metadata` with same access as viewing.
6. **Stream** — `GET /stream/{ticket}` on the PDF service with headers `X-DEK`, `X-Nonce`, `X-Tag` (base64) from metadata. Expect `200` PDF; ticket is single-use via `POST /api/internal/tickets/mark-used` (called from FastAPI).
7. **Revoke** — `POST /api/documents/{id}/revoke` with one grantee identifier; ticket/metadata should fail afterward for that grantee.

## UI (`npm run dev` on port 3000)

Sign in → Dashboard (list, upload, grant/revoke for owned docs) → View opens pdf.js canvas route. Spring and FastAPI URLs default to Vite proxy (`/api`, `/stream`) when `REACT_APP_*` are unset at build time.

## Security notes

- Plain PDF is not served directly; storage holds encrypted blobs.
- Rotate `APP_INTERNAL_API_KEY` and `APP_JWT_SECRET` outside demos; enable IP pinning only when client IP is consistent end-to-end (`APP_SECURITY_IP_PINNING_ENABLED`).
