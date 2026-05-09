-- One-time upgrade for databases initialized before valid_from existed.
-- Safe to re-run: skips if column or constraint already matches.
ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS valid_expiry;

ALTER TABLE access_grant ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ;

UPDATE access_grant SET valid_from = created_at WHERE valid_from IS NULL;

ALTER TABLE access_grant ALTER COLUMN valid_from SET DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE access_grant ALTER COLUMN valid_from SET NOT NULL;

ALTER TABLE access_grant DROP CONSTRAINT IF EXISTS valid_grant_window;

ALTER TABLE access_grant
  ADD CONSTRAINT valid_grant_window CHECK (expires_at > valid_from);
