# CONTRIBUTING.md

## Purpose
This document defines project-level conventions, security requirements, and contribution workflows for the P3_System_Dostepu_Pdf repository. All contributors must follow these rules to ensure consistent style, maintainability, and security compliance.

## Guidelines
- Be respectful and descriptive in issues and PRs.
- Open a dedicated feature branch per change: `feature/<short-description>`.
- All PRs must reference at least one issue and include a clear description of changes.
- Include unit and integration tests for new features and bug fixes.

## Coding Standards
- Follow the project's `.editorconfig`. If missing, create one and follow its rules exactly.
- Prefer C# for new backend/service integration code if not otherwise specified; otherwise follow the language already used in the repository.
- Use consistent naming: PascalCase for public types and methods, camelCase for local variables and private fields (unless `.editorconfig` specifies otherwise).
- Limit line length to 120 characters unless readability dictates otherwise.

## Security Requirements
- All passwords must be hashed using a strong salted algorithm such as bcrypt, Argon2, or PBKDF2. Do not implement custom hashing algorithms.
- AES-256 must be used for encrypting PDF content at rest.
- Do not commit secrets (keys, passwords, tokens) into the repository. Use environment variables or a secrets manager.
- API authentication tokens must have expiration and be revocable.
- Log all access-related events (upload, grant, revoke, open attempts) with sufficient detail to audit.

## Key Management
- Use a Key Management Service (KMS) for the master key, such as HashiCorp Vault, AWS KMS, Azure Key Vault, or Google KMS.
- Do not store raw AES master keys in the repository or in plaintext in environment variables. Store only references or encrypted secrets.
- Each document should have a unique document encryption key (DEK) generated with CSPRNG. The DEK is used to AES-256 encrypt the PDF bytes.
- Store DEKs in the database encrypted with the KMS-managed master key (encrypt the DEK before storing in `DOCUMENT_KEY_METADATA`).
- The FastAPI PDF microservice should request temporary access to decrypted DEKs from the backend (Spring Boot) via a secure mTLS-protected API or via a short-lived token from the KMS.

## Database Schema Practices
- Use explicit column types, NOT NULL where appropriate, and explicit foreign keys.
- Use UTC for all timestamps and store time zone info when applicable.
- Ensure indexing on columns used for access queries and expiration checks.

## Logging & Auditing
- Write all access operations to `ACCESS_EVENT_LOG` with: timestamp (UTC), user id, document id, action (upload/grant/revoke/open_attempt), result (success/failure), IP address, and reason for denial if applicable.
- Logs required for security must be append-only and protected with least privilege.

## Rate Limiting & Lockout Policy
- Implement per-user rate limits for failed access attempts (e.g., 5 failed attempts within 15 minutes -> temporary lockout for 30 minutes).
- Log each failed access attempt in `ACCESS_EVENT_LOG`.

## API Design
- Follow RESTful endpoints. Use `/documents`, `/documents/{id}/grant`, `/documents/{id}/revoke`, `/documents/{id}/open-ticket`, `/documents/{id}/status`, `/logs/access-events` as canonical endpoints.
- Use token-based authentication (JWT with rotation or session tokens with server-side revocation) and always validate authorization server-side.

## Testing
- Unit tests are required for business logic, especially around access control and key handling.
- Integration tests should cover the full upload->grant->open flow, including expiration logic.

## Pull Request Requirements
- All PRs must pass CI, including static analysis, unit tests, and integration tests when applicable.
- Include a short description of security consequences for changes affecting encryption or auth.

## Incident Response
- If a secret or key is accidentally committed, rotate the key immediately and follow incident response steps. Notify maintainers and update the incident log.

## Contacts
- Maintainers: repository owners listed in the GitHub repository settings.