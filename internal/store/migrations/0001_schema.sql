-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Registrants allowed to register, keyed by SPIFFE identity.
CREATE TABLE allow_list (
  id         uuid PRIMARY KEY,
  spiffe_id  text NOT NULL,
  prefixes   text[] NOT NULL DEFAULT '{}',
  names      text[] NOT NULL DEFAULT '{}',
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE UNIQUE INDEX allow_list_active_spiffe ON allow_list (spiffe_id) WHERE revoked_at IS NULL;

-- Operator marks on modules (draining / revoked). One active mark per module.
CREATE TABLE module_marks (
  id         uuid PRIMARY KEY,
  module     text NOT NULL,
  mark       text NOT NULL CHECK (mark IN ('draining','revoked')),
  reason     text NOT NULL DEFAULT '',
  set_by     text NOT NULL DEFAULT '',
  set_at     timestamptz NOT NULL DEFAULT now(),
  cleared_at timestamptz
);
CREATE UNIQUE INDEX module_marks_active ON module_marks (module) WHERE cleared_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS module_marks, allow_list;
