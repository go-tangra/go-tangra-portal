-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
    GRANT USAGE ON SCHEMA public TO gateway_app;
    GRANT SELECT, INSERT, UPDATE ON allow_list, module_marks TO gateway_app;
    GRANT SELECT, INSERT ON gateway_audit_events TO gateway_app;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
