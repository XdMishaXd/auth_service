-- +goose Up
-- +goose StatementBegin
INSERT INTO apps (id, name, secret)
VALUES (
		1,
		'default_app',
		'Uzk86g+2SJXyFp6OjaEJF93NYW6UH71GZBW/WhbbShs='
	) ON CONFLICT (name) DO NOTHING;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DELETE FROM apps
WHERE id = 1
	AND name = 'default_app';
-- +goose StatementEnd
