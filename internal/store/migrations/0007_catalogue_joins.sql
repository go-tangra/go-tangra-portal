-- +goose Up
-- Join bundles made by the add-module wizard (spec 036): which module and
-- version, the enrolment token's jti (never the token), who made it and when
-- the token expires. Used for install progress; kept 24 h past expiry.
CREATE TABLE catalogue_joins (
  id         uuid PRIMARY KEY,
  module     text NOT NULL,
  version    text NOT NULL,
  jti        uuid NOT NULL,
  minted_by  text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX catalogue_joins_expires ON catalogue_joins (expires_at);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT SELECT, INSERT, DELETE ON catalogue_joins TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS catalogue_joins;
