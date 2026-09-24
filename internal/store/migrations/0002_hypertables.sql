-- +goose Up
CREATE TABLE gateway_audit_events (
  ts             timestamptz NOT NULL,
  event_type     text NOT NULL,
  module         text NOT NULL DEFAULT '',
  actor_kind     text NOT NULL CHECK (actor_kind IN ('service','operator','user','system')),
  actor_id       text NOT NULL DEFAULT '',
  tenant_id      uuid,
  subject_kind   text NOT NULL DEFAULT '',
  subject_id     text NOT NULL DEFAULT '',
  outcome        text NOT NULL CHECK (outcome IN ('ok','refused','failed')),
  reason         text NOT NULL DEFAULT '',
  correlation_id text NOT NULL DEFAULT '',
  details        jsonb NOT NULL DEFAULT '{}'::jsonb
);
SELECT create_hypertable('gateway_audit_events', 'ts', chunk_time_interval => INTERVAL '7 days');
CREATE INDEX gateway_audit_module_ts ON gateway_audit_events (module, ts DESC);
CREATE INDEX gateway_audit_type_ts ON gateway_audit_events (event_type, ts DESC);
SELECT add_retention_policy('gateway_audit_events', INTERVAL '400 days');

-- +goose Down
DROP TABLE IF EXISTS gateway_audit_events;
