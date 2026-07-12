package postgres

import (
	"context"
	"errors"
	"fmt"

	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// * SaveOAuthAccount связывает существующего user_id с provider-аккаунтом.
func (r *PostgresRepo) SaveOAuthAccount(
	ctx context.Context,
	userID int64,
	provider string,
	providerUserID string,
	email string,
) error {
	const op = "storage.postgres.SaveOAuthAccount"

	query := `
		INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.pool.Exec(ctx, query, userID, provider, providerUserID, email)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "uq_oauth_provider_user":
				return storage.ErrOAuthAccountAlreadyLinked
			case "uq_oauth_user_provider":
				return storage.ErrOAuthProviderAlreadyLinked
			}
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * OAuthAccountByProviderUserID — основной lookup при login через OAuth.
func (r *PostgresRepo) OAuthAccountByProviderUserID(
	ctx context.Context,
	provider string,
	providerUserID string,
) (*models.OAuthAccount, error) {
	const op = "storage.postgres.OAuthAccountByProviderUserID"

	query := `
		SELECT id, user_id, provider, provider_user_id, email, created_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2
	`

	var a models.OAuthAccount
	err := r.pool.QueryRow(ctx, query, provider, providerUserID).Scan(
		&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.Email, &a.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrOAuthAccountNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &a, nil
}

// * OAuthAccountsByUserID — список привязанных провайдеров, для профиля/настроек.
func (r *PostgresRepo) OAuthAccountsByUserID(ctx context.Context, userID int64) ([]*models.OAuthAccount, error) {
	const op = "storage.postgres.OAuthAccountsByUserID"

	query := `
		SELECT id, user_id, provider, provider_user_id, email, created_at
		FROM oauth_accounts
		WHERE user_id = $1
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	accounts, err := pgx.CollectRows(rows, pgx.RowToStructByName[*models.OAuthAccount])
	if err != nil {
		return nil, fmt.Errorf("%s: collect: %w", op, err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return accounts, nil
}

// * UnlinkOAuthAccount отвязывает provider от юзера.
func (r *PostgresRepo) UnlinkOAuthAccount(ctx context.Context, userID int64, provider string) error {
	const op = "storage.postgres.UnlinkOAuthAccount"

	query := `
		DELETE FROM oauth_accounts
		WHERE user_id = $1 AND provider = $2
	`

	res, err := r.pool.Exec(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if res.RowsAffected() == 0 {
		return storage.ErrOAuthAccountNotFound
	}

	return nil
}

// * SaveOAuthUser регистрирует юзера, у которого ещё нет аккаунта, через OAuth.
func (r *PostgresRepo) SaveOAuthUser(
	ctx context.Context,
	email, username string,
	provider string,
	providerUserID string,
) (int64, error) {
	const op = "storage.postgres.SaveOAuthUser"

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer func() {
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			r.log.Error("rollback failed", sl.Err(rbErr))
		}
	}()

	insertUser := `
		INSERT INTO users (email, username, password_hash, is_verified)
		VALUES ($1, $2, NULL, TRUE)
		RETURNING id
	`

	var userID int64
	if err := tx.QueryRow(ctx, insertUser, email, username).Scan(&userID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, storage.ErrUserAlreadyExists
		}

		return 0, fmt.Errorf("%s: insert user: %w", op, err)
	}

	insertOAuth := `
		INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email)
		VALUES ($1, $2, $3, $4)
	`
	if _, err := tx.Exec(ctx, insertOAuth, userID, provider, providerUserID, email); err != nil {
		return 0, fmt.Errorf("%s: insert oauth account: %w", op, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("%s: commit: %w", op, err)
	}

	return userID, nil
}
