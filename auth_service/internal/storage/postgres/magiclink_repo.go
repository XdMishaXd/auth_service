package postgres

import (
	"context"
	"errors"
	"fmt"

	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/jackc/pgx/v5"
)

// * SaveMagicLink сохраняет magic link
func (r *PostgresRepo) SaveMagicLink(ctx context.Context, link *models.MagicLink) error {
	const op = "storage.postgres.SaveMagicLink"

	query := `
		INSERT INTO magic_links (
			user_id, 
			app_id, 
			token_hash, 
			session_id, 
			expires_at
		) VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(
		ctx,
		query,
		link.UserID,
		link.AppID,
		link.TokenHash,
		link.SessionID,
		link.ExpiresAt,
	).Scan(&link.ID, &link.CreatedAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * ConsumeMagicLink атомарно проверяет и инвалидирует magic link по хешу токена.
func (r *PostgresRepo) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*models.MagicLink, error) {
	const op = "storage.postgres.ConsumeMagicLink"

	query := `
		UPDATE magic_links
		SET used_at = NOW()
		WHERE token_hash = $1
			AND used_at IS NULL
			AND expires_at > NOW()
		RETURNING id, user_id, app_id, token_hash, session_id, used_at, expires_at, created_at
	`

	link := &models.MagicLink{}

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&link.ID, &link.UserID, &link.AppID, &link.TokenHash, &link.SessionID,
		&link.UsedAt, &link.ExpiresAt, &link.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrMagicLinkNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return link, nil
}

// * InvalidateMagicLinksByUserID инвалидирует все активные magic links пользователя
func (r *PostgresRepo) InvalidateMagicLinksByUserID(ctx context.Context, userID int64) (int64, error) {
	const op = "storage.postgres.InvalidateMagicLinksByUserID"

	query := `
		UPDATE magic_links
		SET used_at = NOW()
		WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return result.RowsAffected(), nil
}

// * EnableMagicLink2FA включает magic-link 2FA пользователю.
func (r *PostgresRepo) EnableMagicLink2FA(ctx context.Context, userID int64) error {
	const op = "storage.postgres.EnableMagicLink2FA"

	query := `
		UPDATE users
		SET is_2fa_enabled = TRUE,
			two_fa_method = 'magic_link',
			two_fa_enabled_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if result.RowsAffected() == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

// * DisableMagicLink2FA отключает 2FA пользователю.
func (r *PostgresRepo) DisableMagicLink2FA(ctx context.Context, userID int64) error {
	const op = "storage.postgres.DisableMagicLink2FA"

	query := `
		UPDATE users
		SET is_2fa_enabled = FALSE,
			two_fa_method = NULL,
			two_fa_enabled_at = NULL
		WHERE id = $1 AND deleted_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if result.RowsAffected() == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

func (r *PostgresRepo) TwoFAStatus(ctx context.Context, userID int64) (*models.TwoFAStatus, error) {
	const op = "storage.postgres.TwoFAStatus"

	query := `
		SELECT is_2fa_enabled, two_fa_method, (password_hash IS NOT NULL) AS has_password
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`

	status := &models.TwoFAStatus{}

	err := r.pool.QueryRow(ctx, query, userID).Scan(&status.IsEnabled, &status.Method, &status.HasPassword)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return status, nil
}

// * CleanupExpiredMagicLinks вызывает функцию БД для очистки истекших ссылок
func (r *PostgresRepo) CleanupExpiredMagicLinks(ctx context.Context) (int, error) {
	const op = "storage.postgres.CleanupExpiredMagicLinks"

	query := `SELECT cleanup_expired_magic_links()`

	var deleted int
	err := r.pool.QueryRow(ctx, query).Scan(&deleted)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return deleted, nil
}
