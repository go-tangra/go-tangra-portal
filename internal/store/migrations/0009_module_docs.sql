-- +goose Up
-- Module documentation (help pages). Modules ship Markdown in their binaries
-- (helpdocs bundle); the gateway fetches the bundle when the registered docs
-- digest changes, renders and sanitizes it, and keeps it here for the portal's
-- help browser and full-text search.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE module_docs (
  module     text NOT NULL,
  slug       text NOT NULL,
  lang       text NOT NULL DEFAULT 'en',
  kind       text NOT NULL CHECK (kind IN ('guide', 'example', 'reference', 'faq')),
  audience   text NOT NULL DEFAULT 'user' CHECK (audience IN ('user', 'operator')),
  title      text NOT NULL,
  summary    text NOT NULL DEFAULT '',
  tags       text[] NOT NULL DEFAULT '{}',
  requires   text,                         -- module-local resource:action; NULL = everyone
  ord        integer NOT NULL DEFAULT 0,
  headings   text NOT NULL DEFAULT '',     -- h2/h3 text, for search
  outline    jsonb NOT NULL DEFAULT '[]',  -- [{id, text, level}]
  body       text NOT NULL DEFAULT '',     -- plain text, for search and snippets
  html       text NOT NULL,                -- rendered and sanitized
  digest     text NOT NULL,                -- bundle digest the row came from
  updated_at timestamptz NOT NULL,
  -- Filled on insert, not GENERATED: the text-search configuration depends on
  -- lang (en → english, anything else → simple). Weights: A title,
  -- B summary + tags + headings, C body, D a copy of all text with . and _
  -- split, so parts of identifiers like jobs.lease_seconds match.
  tsv        tsvector NOT NULL,
  PRIMARY KEY (module, slug, lang)
);
CREATE INDEX module_docs_tsv ON module_docs USING gin (tsv);
CREATE INDEX module_docs_title_trgm ON module_docs USING gin (title gin_trgm_ops);

CREATE TABLE module_doc_assets (
  module text NOT NULL,
  path   text NOT NULL,
  mime   text NOT NULL,
  sha256 text NOT NULL,
  bytes  bytea NOT NULL,
  PRIMARY KEY (module, path)
);

-- What is indexed per module (status, ops view). digest is the indexed
-- bundle ('' before the first success); error is the last failure, cleared on
-- success.
CREATE TABLE module_docs_state (
  module     text PRIMARY KEY,
  digest     text NOT NULL DEFAULT '',
  indexed_at timestamptz,
  error      text,
  error_at   timestamptz,
  page_count integer NOT NULL DEFAULT 0
);
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON module_docs, module_doc_assets, module_docs_state TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS module_docs_state;
DROP TABLE IF EXISTS module_doc_assets;
DROP TABLE IF EXISTS module_docs;
