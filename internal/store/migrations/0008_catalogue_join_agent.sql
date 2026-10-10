-- +goose Up
-- Join bundles delivered by an inventory agent (spec 037): the host and the
-- host inputs (not secret) are kept so the bundle can be rendered when the
-- agent fetches it; the token, and so its jti, exist only from that moment.
ALTER TABLE catalogue_joins
  ADD COLUMN channel   text  NOT NULL DEFAULT 'download' CHECK (channel IN ('download', 'agent')),
  ADD COLUMN tenant_id uuid,
  ADD COLUMN host_id   uuid,
  ADD COLUMN inputs    jsonb,
  ADD COLUMN renders   integer NOT NULL DEFAULT 0,
  ALTER COLUMN jti DROP NOT NULL;
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT UPDATE ON catalogue_joins TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DELETE FROM catalogue_joins WHERE jti IS NULL;
ALTER TABLE catalogue_joins
  ALTER COLUMN jti SET NOT NULL,
  DROP COLUMN renders,
  DROP COLUMN inputs,
  DROP COLUMN host_id,
  DROP COLUMN tenant_id,
  DROP COLUMN channel;
