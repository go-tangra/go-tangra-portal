-- +goose Up
-- Module catalogue, phase 2 (spec 035): GitHub owners whose repositories may
-- be catalogue sources, the sources, and the release entries verified from
-- them (with the bundle each entry pins).
CREATE TABLE catalogue_allowed_owners (
  owner    text PRIMARY KEY,
  added_by text NOT NULL DEFAULT '',
  added_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE catalogue_sources (
  repo            text PRIMARY KEY,          -- owner/repo
  added_by        text NOT NULL DEFAULT '',
  added_at        timestamptz NOT NULL DEFAULT now(),
  module          text UNIQUE,               -- bound by the first verified entry
  last_checked_at timestamptz,
  last_error      text NOT NULL DEFAULT ''
);
CREATE TABLE catalogue_entries (
  module        text NOT NULL,
  version       text NOT NULL,
  repo          text NOT NULL,
  version_key   bigint NOT NULL,             -- major*1e12 + minor*1e6 + patch, for ordering
  entry         jsonb NOT NULL,
  entry_sha256  text NOT NULL,
  bundle        bytea NOT NULL,
  bundle_sha256 text NOT NULL,
  attested_by   text NOT NULL,
  verified_at   timestamptz NOT NULL,
  PRIMARY KEY (module, version)
);
CREATE INDEX catalogue_entries_latest ON catalogue_entries (module, version_key DESC);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_allowed_owners, catalogue_sources TO gateway_app;
    GRANT SELECT, INSERT ON catalogue_entries TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS catalogue_entries, catalogue_sources, catalogue_allowed_owners;
