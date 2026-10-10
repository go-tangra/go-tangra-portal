-- +goose Up
-- Modules the gateway has seen register. The leased registry forgets a
-- module when its last instance leaves; this record keeps it, so a module
-- that is installed but down stays visible (gateway module catalogue, phase 1).
CREATE TABLE known_modules (
  module        text PRIMARY KEY,
  identity      text NOT NULL,
  display_name  text NOT NULL DEFAULT '',
  last_version  text NOT NULL DEFAULT '',   -- newest build version seen
  manifest_hash text NOT NULL DEFAULT '',
  first_seen_at timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  expected      boolean NOT NULL DEFAULT true,  -- administrators: should be running
  forgotten_at  timestamptz                     -- administrators removed it
);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT SELECT, INSERT, UPDATE ON known_modules TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS known_modules;
