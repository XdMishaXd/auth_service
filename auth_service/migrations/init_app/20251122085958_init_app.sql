-- +goose Up
-- +goose StatementBegin
INSERT INTO apps (id, name, secret)
VALUES (1, 'default_app', 'super-secret-key') ON CONFLICT (name) DO NOTHING;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DELETE FROM apps
WHERE id = 1
	AND name = 'default_app';
-- +goose StatementEnd
