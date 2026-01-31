-- +goose Up
-- +goose StatementBegin

-- Создание таблицы magic_links для хранения одноразовых ссылок 2FA
CREATE TABLE magic_links (
	id BIGSERIAL PRIMARY KEY,
	user_id BIGINT NOT NULL,
	app_id INTEGER NOT NULL,
	token_hash VARCHAR(64) NOT NULL UNIQUE,
	session_id VARCHAR(64) NOT NULL,
	ip_address INET,
	user_agent TEXT,
	used BOOLEAN DEFAULT false NOT NULL,
	used_at TIMESTAMP,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP DEFAULT NOW() NOT NULL,

	-- Внешние ключи
	CONSTRAINT fk_magic_links_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
	CONSTRAINT fk_magic_links_app FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

-- Индекс для быстрого поиска по хешу токена (основной use case)
CREATE INDEX idx_magic_links_token_hash ON magic_links(token_hash)
WHERE used = false;

-- Индекс для поиска активных ссылок пользователя
CREATE INDEX idx_magic_links_user_active ON magic_links(user_id, used, expires_at)
WHERE used = false AND expires_at > NOW();

-- Индекс для очистки истекших токенов
CREATE INDEX idx_magic_links_expires ON magic_links(expires_at)
WHERE used = false;

-- Индекс для поиска по session_id 
CREATE INDEX idx_magic_links_session_id ON magic_links(session_id);

-- Функция для ограничения количества активных magic links на пользователя
CREATE OR REPLACE FUNCTION limit_active_magic_links() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE active_count INTEGER;
BEGIN -- Подсчитываем активные неиспользованные ссылки для пользователя
SELECT COUNT(*) INTO active_count
FROM magic_links
WHERE user_id = NEW.user_id
	AND used = false
	AND expires_at > NOW();
-- Если больше 3 активных ссылок - удаляем самые старые
IF active_count >= 3 THEN
DELETE FROM magic_links
WHERE id IN (
		SELECT id
		FROM magic_links
		WHERE user_id = NEW.user_id
			AND used = false
			AND expires_at > NOW()
		ORDER BY created_at ASC
		LIMIT (active_count - 2)
	);
END IF;
RETURN NEW;
END;
$$;

-- Триггер для автоматического ограничения активных ссылок
CREATE TRIGGER trg_limit_magic_links BEFORE
INSERT ON magic_links FOR EACH ROW EXECUTE FUNCTION limit_active_magic_links();

-- Функция для автоматической очистки истекших magic links
CREATE OR REPLACE FUNCTION cleanup_expired_magic_links() RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE deleted_count INTEGER;
BEGIN
DELETE FROM magic_links
WHERE expires_at < NOW() - INTERVAL '1 day'
	AND used = false;
GET DIAGNOSTICS deleted_count = ROW_COUNT;
RETURN deleted_count;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Удаление триггера
DROP TRIGGER IF EXISTS trg_limit_magic_links ON magic_links;

-- Удаление функций
DROP FUNCTION IF EXISTS limit_active_magic_links();
DROP FUNCTION IF EXISTS cleanup_expired_magic_links();

-- Удаление таблицы
DROP TABLE IF EXISTS magic_links CASCADE;
-- +goose StatementEnd
