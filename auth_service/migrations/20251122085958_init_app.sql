-- +goose Up
-- +goose StatementBegin
INSERT INTO apps (id, name, secret)
VALUES (1, 'default_app', 'super-secret-key')
ON CONFLICT (name) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS apps;
-- +goose StatementEnd
