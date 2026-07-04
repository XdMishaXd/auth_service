-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;
-- ==========================================================
-- Users
-- ==========================================================
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL CONSTRAINT pk_users PRIMARY KEY,
  email CITEXT NOT NULL CONSTRAINT uq_users_email UNIQUE,
  username CITEXT NOT NULL CONSTRAINT uq_users_username UNIQUE,
  password_hash TEXT NOT NULL,
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- ==========================================================
-- Applications
-- ==========================================================
CREATE TABLE IF NOT EXISTS apps (
  id BIGSERIAL CONSTRAINT pk_apps PRIMARY KEY,
  name TEXT NOT NULL CONSTRAINT uq_apps_name UNIQUE,
  secret TEXT NOT NULL CONSTRAINT uq_apps_secret UNIQUE
);
-- ==========================================================
-- updated_at trigger
-- ==========================================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN NEW.updated_at = NOW();
RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at BEFORE
UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- ==========================================================
-- Refresh Tokens
-- ==========================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
  -- публичный идентификатор токена (идёт в самом refresh token)
  id UUID CONSTRAINT pk_refresh_tokens PRIMARY KEY,
  -- быстрый поиск по токену (SHA-256 от secret части)
  token_hash BYTEA NOT NULL CONSTRAINT uq_refresh_tokens_hash UNIQUE,
  user_id BIGINT NOT NULL,
  app_id BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT chk_refresh_tokens_expiration CHECK (expires_at > created_at),
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_app FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);
-- быстрый поиск токенов пользователя (например, список сессий)
-- CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
-- чистка просроченных токенов
CREATE INDEX idx_refresh_tokens_active_expires ON refresh_tokens (expires_at);
-- полезно для revoke / cleanup конкретного пользователя
-- CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_app ON refresh_tokens(user_id, app_id);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();
DROP TABLE IF EXISTS apps;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
