-- +goose Up
-- A unique id gives audit pages a total, stable order (events can share a
-- timestamp) and backs the default newest-first listing.
ALTER TABLE gateway_audit_events ADD COLUMN IF NOT EXISTS id bigserial;
CREATE INDEX IF NOT EXISTS gateway_audit_ts_id ON gateway_audit_events (ts DESC, id DESC);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT USAGE ON SEQUENCE gateway_audit_events_id_seq TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX IF EXISTS gateway_audit_ts_id;
ALTER TABLE gateway_audit_events DROP COLUMN IF EXISTS id;
