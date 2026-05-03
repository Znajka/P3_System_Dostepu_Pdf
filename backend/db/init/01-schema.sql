-- ============================================================================
-- P3 System Dostepu PDF - PostgreSQL Schema
-- ============================================================================
-- Enforces:
-- - AES-256 envelope encryption for DEKs
-- - Audit logging with append-only semantics
-- - Rate-limiting and account lockout
-- - Role-based access control (ADMIN, USER); document ownership is per-document
-- - UTC timestamps with proper indexing
-- ============================================================================

-- Set up extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enums for role-based access
CREATE TYPE user_role AS ENUM ('ADMIN', 'USER');
CREATE TYPE access_action AS ENUM (
  'upload',
  'grant',
  'revoke',
  'open_attempt',
  'stream_start',
  'stream_end'
);
CREATE TYPE access_result AS ENUM ('success', 'failure');

-- ============================================================================
-- USER table
-- ============================================================================
-- Stores user identity, roles, password hashes, and rate-limit/lockout state.
-- Passwords are hashed with bcrypt/Argon2 (never plaintext).
-- Rate-limiting: tracks failed_attempts and lock_until for account lockout.
-- ============================================================================
CREATE TABLE "user" (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(255) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  roles user_role[] NOT NULL DEFAULT '{USER}'::user_role[],
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  lock_until TIMESTAMP WITH TIME ZONE,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_user_username ON "user"(username);
CREATE INDEX idx_user_email ON "user"(email);
CREATE INDEX idx_user_lock_until ON "user"(lock_until) WHERE lock_until IS NOT NULL;
CREATE INDEX idx_user_active ON "user"(active) WHERE active = true;

-- ============================================================================
-- DOCUMENT table
-- ============================================================================
-- Stores document metadata: title, owner, creation time, and encryption indicator.
-- Encrypted PDF blob is stored externally (object store or filesystem).
-- blob_path references the encrypted file location (not directly accessible).
-- ============================================================================
CREATE TABLE document (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  tags VARCHAR(255)[],
  blob_path VARCHAR(511) NOT NULL,
  blob_size_bytes BIGINT NOT NULL,
  encrypted_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_document_owner_id ON document(owner_id);
CREATE INDEX idx_document_created_at ON document(created_at);
CREATE INDEX idx_document_deleted_at ON document(deleted_at) WHERE deleted_at IS NULL;

-- ============================================================================
-- DOCUMENT_KEY_METADATA table
-- ============================================================================
-- Stores per-document encryption key metadata (DEK wrapped by KMS master key).
-- CRITICAL SECURITY:
--   - wrapped_dek: AES-256 DEK encrypted by KMS master key (never plaintext).
--   - wrap_algorithm: key wrapping algorithm (e.g., "AES-KW", "RSA-OAEP").
--   - iv: initialization vector for wrapped DEK.
--   - tag: authentication tag (GCM).
--   - kms_metadata: JSON metadata from KMS (key_id, wrap_date, key_version).
-- One row per document; append-only (no updates, only inserts for new versions).
-- ============================================================================
CREATE TABLE document_key_metadata (
  document_id UUID PRIMARY KEY REFERENCES document(id) ON DELETE RESTRICT,
  wrapped_dek BYTEA NOT NULL,
  wrap_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-KW',
  iv BYTEA NOT NULL,
  tag BYTEA NOT NULL,
  kms_key_id VARCHAR(255) NOT NULL,
  kms_key_version VARCHAR(50),
  kms_metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_wrapped_dek CHECK (octet_length(wrapped_dek) > 0),
  CONSTRAINT valid_iv CHECK (octet_length(iv) > 0),
  CONSTRAINT valid_tag CHECK (octet_length(tag) > 0)
);

CREATE INDEX idx_document_key_metadata_kms_key_id ON document_key_metadata(kms_key_id);

-- ============================================================================
-- ACCESS_GRANT table
-- ============================================================================
-- Stores document access grants: which user has access to which document.
-- expires_at enforced server-side; access is revoked by setting revoked_flag.
-- Only document owner or ADMIN can grant/revoke (enforced in application).
-- ============================================================================
CREATE TABLE access_grant (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  document_id UUID NOT NULL REFERENCES document(id) ON DELETE RESTRICT,
  grantee_user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
  granted_by_user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  revoked_at TIMESTAMP WITH TIME ZONE,
  revoked_by_user_id UUID REFERENCES "user"(id) ON DELETE SET NULL,
  revoke_reason VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT no_self_grant CHECK (grantee_user_id != granted_by_user_id),
  CONSTRAINT valid_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_access_grant_document_id ON access_grant(document_id);
CREATE INDEX idx_access_grant_grantee_user_id ON access_grant(grantee_user_id);
CREATE INDEX idx_access_grant_expires_at ON access_grant(expires_at) WHERE revoked = false;
CREATE INDEX idx_access_grant_revoked ON access_grant(revoked);
CREATE UNIQUE INDEX idx_access_grant_unique_active ON access_grant(
  document_id,
  grantee_user_id
) WHERE revoked = false;

-- ============================================================================
-- ACCESS_EVENT_LOG table
-- ============================================================================
-- APPEND-ONLY audit log: records all security-relevant events.
-- Events: upload, grant, revoke, open_attempt, stream_start, stream_end.
-- IMMUTABLE: no updates or deletes after insertion (enforce at application level).
-- Fields: timestamp (UTC), user_id, document_id, action, result, ip, reason.
-- ============================================================================
CREATE TABLE access_event_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  timestamp_utc TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id UUID REFERENCES "user"(id) ON DELETE SET NULL,
  document_id UUID REFERENCES document(id) ON DELETE SET NULL,
  action access_action NOT NULL,
  result access_result NOT NULL,
  ip_address INET,
  user_agent VARCHAR(512),
  reason VARCHAR(255),
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_event_log_timestamp_utc ON access_event_log(timestamp_utc DESC);
CREATE INDEX idx_access_event_log_user_id ON access_event_log(user_id);
CREATE INDEX idx_access_event_log_document_id ON access_event_log(document_id);
CREATE INDEX idx_access_event_log_action ON access_event_log(action);
CREATE INDEX idx_access_event_log_result ON access_event_log(result);
CREATE INDEX idx_access_event_log_user_document_action ON access_event_log(
  user_id,
  document_id,
  action
) WHERE result = 'failure';

-- ============================================================================
-- SESSION_TOKEN table
-- ============================================================================
-- Stores server-side session or token metadata for revocation.
-- Token hashes stored (never plaintext tokens in DB).
-- Used for session invalidation and refresh token rotation.
-- ============================================================================
CREATE TABLE session_token (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  token_type VARCHAR(50) NOT NULL DEFAULT 'Bearer',
  issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  revoked_at TIMESTAMP WITH TIME ZONE,
  ip_address INET,
  user_agent VARCHAR(512),
  jti VARCHAR(255) UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_expiry CHECK (expires_at > issued_at)
);

CREATE INDEX idx_session_token_user_id ON session_token(user_id);
CREATE INDEX idx_session_token_expires_at ON session_token(expires_at) WHERE revoked = false;
CREATE INDEX idx_session_token_revoked ON session_token(revoked);
CREATE INDEX idx_session_token_jti ON session_token(jti) WHERE revoked = false;

-- ============================================================================
-- RATE_LIMIT_STATE table
-- ============================================================================
-- Tracks per-user failed attempts for open-ticket requests (rate-limiting).
-- Resets on successful grant-based access; incremented on failures.
-- Used to enforce lockout policy (N failures in window -> lock_until).
-- ============================================================================
CREATE TABLE rate_limit_state (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  last_failed_attempt TIMESTAMP WITH TIME ZONE,
  lock_until TIMESTAMP WITH TIME ZONE,
  reset_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rate_limit_state_user_id ON rate_limit_state(user_id);
CREATE INDEX idx_rate_limit_state_lock_until ON rate_limit_state(lock_until) WHERE lock_until IS NOT NULL;

-- ============================================================================
-- TICKET_NONCE table
-- ============================================================================
-- Stores single-use ticket nonces to prevent replay attacks.
-- Nonce = jti (JWT ID) from open-ticket response.
-- Marked as used after first successful FastAPI validation.
-- Expires after ticket TTL + buffer.
-- ============================================================================
CREATE TABLE ticket_nonce (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  nonce VARCHAR(255) NOT NULL UNIQUE,
  document_id UUID NOT NULL REFERENCES document(id) ON DELETE RESTRICT,
  user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE RESTRICT,
  used BOOLEAN NOT NULL DEFAULT false,
  used_at TIMESTAMP WITH TIME ZONE,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_nonce_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_ticket_nonce_nonce ON ticket_nonce(nonce) WHERE used = false;
CREATE INDEX idx_ticket_nonce_expires_at ON ticket_nonce(expires_at) WHERE used = false;
CREATE INDEX idx_ticket_nonce_user_document ON ticket_nonce(user_id, document_id) WHERE used = false;

-- ============================================================================
-- Materialized Views & Functions
-- ============================================================================

-- Materialized view: current active access grants (not revoked, not expired)
CREATE MATERIALIZED VIEW active_grants AS
SELECT
  ag.id,
  ag.document_id,
  ag.grantee_user_id,
  ag.granted_by_user_id,
  ag.expires_at,
  d.owner_id AS document_owner_id,
  u.username AS grantee_username
FROM access_grant ag
JOIN document d ON ag.document_id = d.id
JOIN "user" u ON ag.grantee_user_id = u.id
WHERE ag.revoked = false
  AND ag.expires_at > CURRENT_TIMESTAMP
  AND d.deleted_at IS NULL;

CREATE INDEX idx_active_grants_document_id ON active_grants(document_id);
CREATE INDEX idx_active_grants_grantee_user_id ON active_grants(grantee_user_id);

-- Function: mark_ticket_used(nonce, used_by_user_id)
CREATE OR REPLACE FUNCTION mark_ticket_used(
  p_nonce VARCHAR,
  p_used_by_user_id UUID
) RETURNS BOOLEAN AS $$
DECLARE
  v_updated BOOLEAN;
BEGIN
  UPDATE ticket_nonce
  SET used = true, used_at = CURRENT_TIMESTAMP
  WHERE nonce = p_nonce
    AND user_id = p_used_by_user_id
    AND used = false
    AND expires_at > CURRENT_TIMESTAMP;
  
  v_updated := FOUND;
  RETURN v_updated;
END;
$$ LANGUAGE plpgsql;

-- Function: increment_failed_attempts(user_id)
-- Returns: true if user is now locked; false if not yet locked.
CREATE OR REPLACE FUNCTION increment_failed_attempts(
  p_user_id UUID,
  p_max_attempts INTEGER DEFAULT 5,
  p_window_minutes INTEGER DEFAULT 15,
  p_lockout_minutes INTEGER DEFAULT 30
) RETURNS BOOLEAN AS $$
DECLARE
  v_current_attempts INTEGER;
  v_now TIMESTAMP WITH TIME ZONE;
  v_window_start TIMESTAMP WITH TIME ZONE;
  v_locked BOOLEAN;
BEGIN
  v_now := CURRENT_TIMESTAMP;
  v_window_start := v_now - (p_window_minutes || ' minutes')::INTERVAL;
  
  -- Get current attempt count in window
  SELECT COUNT(*)
  INTO v_current_attempts
  FROM access_event_log
  WHERE user_id = p_user_id
    AND action = 'open_attempt'
    AND result = 'failure'
    AND timestamp_utc > v_window_start;
  
  -- Increment
  v_current_attempts := v_current_attempts + 1;
  
  -- Check if should lock
  v_locked := v_current_attempts >= p_max_attempts;
  
  IF v_locked THEN
    UPDATE "user"
    SET lock_until = v_now + (p_lockout_minutes || ' minutes')::INTERVAL,
        updated_at = v_now
    WHERE id = p_user_id;
  END IF;
  
  RETURN v_locked;
END;
$$ LANGUAGE plpgsql;

-- Function: is_user_locked(user_id)
CREATE OR REPLACE FUNCTION is_user_locked(p_user_id UUID) RETURNS BOOLEAN AS $$
DECLARE
  v_locked BOOLEAN;
BEGIN
  SELECT (lock_until IS NOT NULL AND lock_until > CURRENT_TIMESTAMP)
  INTO v_locked
  FROM "user"
  WHERE id = p_user_id;
  
  RETURN COALESCE(v_locked, false);
END;
$$ LANGUAGE plpgsql;

-- Function: clear_user_lockout(user_id)
CREATE OR REPLACE FUNCTION clear_user_lockout(p_user_id UUID) RETURNS VOID AS $$
BEGIN
  UPDATE "user"
  SET lock_until = NULL, failed_attempts = 0, updated_at = CURRENT_TIMESTAMP
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Triggers
-- ============================================================================

-- Trigger: update updated_at on user table
CREATE OR REPLACE FUNCTION update_user_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_user_updated_at
BEFORE UPDATE ON "user"
FOR EACH ROW
EXECUTE FUNCTION update_user_updated_at();

-- Trigger: update updated_at on document table
CREATE OR REPLACE FUNCTION update_document_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_document_updated_at
BEFORE UPDATE ON document
FOR EACH ROW
EXECUTE FUNCTION update_document_updated_at();

-- Trigger: update updated_at on access_grant table
CREATE OR REPLACE FUNCTION update_access_grant_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_access_grant_updated_at
BEFORE UPDATE ON access_grant
FOR EACH ROW
EXECUTE FUNCTION update_access_grant_updated_at();

-- Trigger: update updated_at on rate_limit_state table
CREATE OR REPLACE FUNCTION update_rate_limit_state_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_rate_limit_state_updated_at
BEFORE UPDATE ON rate_limit_state
FOR EACH ROW
EXECUTE FUNCTION update_rate_limit_state_updated_at();

-- ============================================================================
-- Role-Based Access Control (Row-Level Security - optional, for production)
-- ============================================================================
-- Enable RLS for sensitive tables. Policies enforced at DB level.
-- NOTE: requires careful policy design; keeping as reference for future use.
-- Uncomment to enable in production.

-- ALTER TABLE access_event_log ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE session_token ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE document_key_metadata ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Grants & Permissions (for application user, not postgres superuser)
-- ============================================================================
-- Uncomment and customize for production deployments.

-- CREATE ROLE p3_app_user WITH LOGIN PASSWORD 'strong-app-password';
-- GRANT CONNECT ON DATABASE p3_system_db TO p3_app_user;
-- GRANT USAGE ON SCHEMA public TO p3_app_user;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO p3_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO p3_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO p3_app_user;

-- CREATE ROLE p3_auditor WITH LOGIN PASSWORD 'strong-auditor-password';
-- GRANT CONNECT ON DATABASE p3_system_db TO p3_auditor;
-- GRANT USAGE ON SCHEMA public TO p3_auditor;
-- GRANT SELECT ON access_event_log TO p3_auditor;
-- GRANT SELECT ON session_token TO p3_auditor;

-- ============================================================================
-- Comments for documentation
-- ============================================================================
COMMENT ON TABLE document_key_metadata IS
'Stores AES-256 DEK wrapped by KMS master key. DEK never stored plaintext.
 Wrap algorithm: AES-KW (key wrap) or RSA-OAEP. IV and tag used for
 authenticated encryption of the DEK itself. CRITICAL: do not expose
 wrapped_dek, iv, or tag to untrusted parties.';

COMMENT ON TABLE access_event_log IS
'APPEND-ONLY audit log. All security-relevant events logged here.
 Do not update or delete rows after insertion (enforce at app level).
 Used for compliance, breach investigation, and rate-limit decisions.';

COMMENT ON COLUMN document_key_metadata.wrapped_dek IS
'AES-256 DEK encrypted by KMS master key. Never plaintext.
 Used only by Spring Boot (via KMS) and FastAPI (via Spring Boot).';

COMMENT ON FUNCTION is_user_locked IS
'Check if user is currently locked due to rate-limit violation.
 Returns true if lock_until > now(); false otherwise.';

COMMENT ON FUNCTION increment_failed_attempts IS
'Increment failed attempt count; lock user if threshold exceeded.
 Parameters: max_attempts (default 5), window_minutes (default 15),
 lockout_minutes (default 30). Respects per-user isolation.';

-- ============================================================================
-- Dev/Test seed users
-- ============================================================================
-- Simple accounts for local demo/testing.
-- Passwords are hashed with bcrypt via pgcrypto.
INSERT INTO "user" (username, email, password_hash, roles, active)
VALUES
  ('admin', 'admin@p3.local', crypt('admin123', gen_salt('bf', 12)), '{ADMIN}'::user_role[], true),
  ('owner1', 'owner1@p3.local', crypt('owner123', gen_salt('bf', 12)), '{USER}'::user_role[], true),
  ('owner2', 'owner2@p3.local', crypt('owner123', gen_salt('bf', 12)), '{USER}'::user_role[], true),
  ('owner3', 'owner3@p3.local', crypt('owner123', gen_salt('bf', 12)), '{USER}'::user_role[], true),
  ('user1', 'user1@p3.local', crypt('user123', gen_salt('bf', 12)), '{USER}'::user_role[], true),
  ('user2', 'user2@p3.local', crypt('user123', gen_salt('bf', 12)), '{USER}'::user_role[], true),
  ('user3', 'user3@p3.local', crypt('user123', gen_salt('bf', 12)), '{USER}'::user_role[], true)
ON CONFLICT (username) DO NOTHING;

-- Seed role mappings used by JPA @ElementCollection table.
INSERT INTO user_roles (user_id, roles)
SELECT id, 'ADMIN' FROM "user" WHERE username = 'admin'
ON CONFLICT DO NOTHING;
INSERT INTO user_roles (user_id, roles)
SELECT id, 'USER' FROM "user" WHERE username IN ('owner1', 'owner2', 'owner3')
ON CONFLICT DO NOTHING;
INSERT INTO user_roles (user_id, roles)
SELECT id, 'USER' FROM "user" WHERE username IN ('user1', 'user2', 'user3')
ON CONFLICT DO NOTHING;