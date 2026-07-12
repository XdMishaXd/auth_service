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
			ip_address, 
			user_agent, 
			expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`

	err := r.pool.QueryRow(
		ctx,
		query,
		link.UserID,
		link.AppID,
		link.TokenHash,
		link.SessionID,
		link.IPAddress,
		link.UserAgent,
		link.ExpiresAt,
	).Scan(&link.ID, &link.CreatedAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * MagicLinkByTokenHash получает magic link по хешу токена
func (r *PostgresRepo) MagicLinkByTokenHash(ctx context.Context, tokenHash []byte) (*models.MagicLink, error) {
	const op = "storage.postgres.MagicLinkByTokenHash"

	query := `
		SELECT 
			id, 
			user_id, 
			app_id, 
			token_hash, 
			session_id, 
			ip_address, 
			user_agent, 
			used, 
			used_at, 
			expires_at, 
			created_at
		FROM magic_links
		WHERE token_hash = $1
	`

	link := &models.MagicLink{}

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&link.ID,
		&link.UserID,
		&link.AppID,
		&link.TokenHash,
		&link.SessionID,
		&link.IPAddress,
		&link.UserAgent,
		&link.Used,
		&link.UsedAt,
		&link.ExpiresAt,
		&link.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrMagicLinkNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return link, nil
}

// * MarkMagicLinkAsUsed помечает magic link как использованный
func (r *PostgresRepo) MarkMagicLinkAsUsed(ctx context.Context, id int64) error {
	const op = "storage.postgres.MarkMagicLinkAsUsed"

	query := `
		UPDATE magic_links 
		SET used = true, 
			used_at = NOW() 
		WHERE id = $1 AND used = false
	`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	rows := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("%s: magic link not found or already used", op)
	}

	return nil
}

// * ActiveMagicLinksByUserID получает активные magic links пользователя
func (r *PostgresRepo) ActiveMagicLinksByUserID(ctx context.Context, userID int64) ([]*models.MagicLink, error) {
	const op = "storage.postgres.ActiveMagicLinksByUserID"

	query := `
		SELECT 
			id, 
			user_id, 
			app_id, 
			token_hash, 
			session_id, 
			ip_address, 
			user_agent, 
			used, 
			used_at, 
			expires_at, 
			created_at
		FROM magic_links
		WHERE user_id = $1 AND used = false AND expires_at > NOW()
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	links, err := pgx.CollectRows(rows, pgx.RowToStructByName[*models.MagicLink])
	if err != nil {
		return nil, fmt.Errorf("%s: collect: %w", op, err)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return links, nil
}

// * InvalidateMagicLinksByUserID инвалидирует все активные magic links пользователя
func (r *PostgresRepo) InvalidateMagicLinksByUserID(ctx context.Context, userID int64) (int64, error) {
	const op = "storage.postgres.InvalidateMagicLinksByUserID"

	query := `
		UPDATE magic_links 
		SET used = true, 
			used_at = NOW() 
		WHERE user_id = $1 AND used = false AND expires_at > NOW()
	`

	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	rows := result.RowsAffected()
	return rows, nil
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
