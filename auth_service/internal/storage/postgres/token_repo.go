package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *PostgresRepo) SaveRefreshToken(
	ctx context.Context,
	id string,
	userID int64,
	appID int32,
	tokenHash []byte,
	expiresAt time.Time,
) error {
	const op = "storage.postgres.SaveRefreshToken"

	query := `
		INSERT INTO refresh_tokens (id, user_id, app_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query,
		id,
		userID,
		appID,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *PostgresRepo) UpdateRefreshToken(
	ctx context.Context,
	id uuid.UUID,
	newTokenHash []byte,
	oldTokenHash []byte,
	expiresAt time.Time,
) error {
	const op = "storage.postgres.UpdateRefreshToken"

	query := `
		UPDATE refresh_tokens
		SET token_hash = $1,
			expires_at = $2
		WHERE id = $3 AND token_hash = $4
	`

	res, err := r.pool.Exec(ctx, query,
		newTokenHash,
		expiresAt,
		id,
		oldTokenHash,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if res.RowsAffected() == 0 {
		return storage.ErrRefreshTokenConflict
	}

	return nil
}

func (r *PostgresRepo) RefreshTokenByID(
	ctx context.Context,
	id uuid.UUID,
) (*models.RefreshToken, error) {
	const op = "storage.postgres.RefreshTokenByID"

	query := `
		SELECT id, user_id, app_id, token_hash, expires_at
		FROM refresh_tokens
		WHERE id = $1
	`

	var rt models.RefreshToken

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.AppID,
		&rt.TokenHash,
		&rt.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &rt, nil
}

func (r *PostgresRepo) DeleteRefreshToken(
	ctx context.Context,
	id uuid.UUID,
) error {
	const op = "storage.postgres.DeleteRefreshToken"

	query := `
		DELETE FROM refresh_tokens
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *PostgresRepo) SaveResetToken(
	ctx context.Context,
	tokenID uuid.UUID,
	userID int64,
	tokenHash []byte,
	expiresAt time.Time,
) error {
	const op = "storage.postgres.App"

	query := `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.pool.Exec(ctx, query,
		tokenID,
		userID,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *PostgresRepo) ResetTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.ResetToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, used_at
		FROM password_reset_tokens
		WHERE id = $1
	`
	var rt models.ResetToken

	err := r.pool.QueryRow(ctx, query, tokenID).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.TokenHash,
		&rt.ExpiresAt,
		&rt.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrResetTokenNotFound
		}

		return nil, fmt.Errorf("scan reset token %s: %w", tokenID, err)
	}

	return &rt, nil
}

func (r *PostgresRepo) DeleteAllResetTokens(ctx context.Context, uid int64) error {
	const op = "postgres.DeleteAllResetTokens"

	query := `
		DELETE
		FROM password_reset_tokens
		WHERE user_id = $1
	`
	_, err := r.pool.Exec(ctx, query, uid)
	if err != nil {
		return fmt.Errorf("%s: failed to save user: %w", op, err)
	}

	return nil
}

func (r *PostgresRepo) ResetPassword(
	ctx context.Context,
	userID int64,
	tokenID uuid.UUID,
	newPasswordHash []byte,
) error {
	const op = "storage.postgres.ResetPassword"

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			r.log.Error("rollback failed", sl.Err(err))
		}
	}()

	const invalidateTokenQuery = `
    UPDATE password_reset_tokens
    SET used_at = NOW()
    WHERE id = $1 AND user_id = $2 AND used_at IS NULL
  `
	res, err := tx.Exec(ctx, invalidateTokenQuery, tokenID, userID)
	if err != nil {
		return fmt.Errorf("%s: invalidate token: %w", op, err)
	}
	if res.RowsAffected() == 0 {
		// Либо уже использован конкурентным запросом, либо не существует/чужой
		return storage.ErrResetTokenUsed
	}

	const updatePasswordQuery = `
    UPDATE users SET password_hash = $1 WHERE id = $2
  `
	res, err = tx.Exec(ctx, updatePasswordQuery, newPasswordHash, userID)
	if err != nil {
		return fmt.Errorf("%s: update password: %w", op, err)
	}
	if res.RowsAffected() == 0 {
		return storage.ErrUserNotFound
	}

	if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("%s: delete refresh tokens: %w", op, err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("%s: delete reset tokens: %w", op, err)
	}

	const invalidateMagicLinksQuery = `
    UPDATE magic_links SET used = TRUE, used_at = NOW()
    WHERE user_id = $1 AND used = FALSE
  `
	if _, err := tx.Exec(ctx, invalidateMagicLinksQuery, userID); err != nil {
		return fmt.Errorf("%s: invalidate magic links: %w", op, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%s: commit: %w", op, err)
	}

	return nil
}
