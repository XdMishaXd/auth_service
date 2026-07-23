package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (r *PostgresRepo) SaveUser(ctx context.Context, email, username string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	query := `
		INSERT INTO users (email, username, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id;
	`

	var id int64

	err := r.pool.QueryRow(ctx, query, email, username, passHash).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, storage.ErrUserAlreadyExists
		}

		return 0, fmt.Errorf("%s: failed to save user: %w", op, err)
	}

	return id, nil
}

func (r *PostgresRepo) User(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.postgres.User"

	query := `
		SELECT id, email, username, password_hash, is_verified, deleted_at
		FROM users
		WHERE email = $1;
	`

	row := r.pool.QueryRow(ctx, query, email)

	var u models.User
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.Username,
		&u.PassHash,
		&u.IsVerified,
		&u.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}

		return nil, fmt.Errorf("%s: failed to get user: %w", op, err)
	}

	return &u, nil
}

func (r *PostgresRepo) UserByID(ctx context.Context, id int64) (*models.User, error) {
	const op = "storage.postgres.UserByID"

	query := `
		SELECT id, email, username, password_hash, is_verified, deleted_at
		FROM users
		WHERE id = $1;
	`

	row := r.pool.QueryRow(ctx, query, id)

	var u models.User
	err := row.Scan(
		&u.ID,
		&u.Email,
		&u.Username,
		&u.PassHash,
		&u.IsVerified,
		&u.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}
		return nil, fmt.Errorf("%s: failed to get user by id: %w", op, err)
	}

	return &u, nil
}

func (r *PostgresRepo) UserByEmail(ctx context.Context, email string) (int64, error) {
	const op = "storage.postgres.UserByEmail"

	query := `
		SELECT id
		FROM users
		WHERE email = $1 AND deleted_at IS NULL;
	`

	var id int64

	err := r.pool.QueryRow(ctx, query, email).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, storage.ErrUserNotFound
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// * CheckIfUserVerified проверяет, подтвердил ли пользователь свой email
func (r *PostgresRepo) CheckIfUserVerified(ctx context.Context, email string) (int64, bool, error) {
	const op = "storage.postgres.CheckIfUserVerified"

	query := `	
		SELECT id, is_verified
		FROM users
		WHERE email = $1 AND deleted_at IS NULL;
	`
	row := r.pool.QueryRow(ctx, query, email)

	var isVerified bool
	var id int64

	err := row.Scan(
		&id,
		&isVerified,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, storage.ErrUserNotFound
		}

		return 0, false, fmt.Errorf("%s: %w", op, err)
	}

	return id, isVerified, nil
}

func (r *PostgresRepo) SetEmailVerified(ctx context.Context, userID int64) error {
	const op = "storage.postgres.SetEmailVerified"

	query := `UPDATE users SET is_verified = TRUE WHERE id = $1 AND deleted_at IS NULL;`

	res, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if res.RowsAffected() == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

func (r *PostgresRepo) DeleteAccount(ctx context.Context, userID int64) error {
	const op = "storage.postgres.DeleteAccount"

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			r.log.Error("rollback failed", sl.Err(err))
		}
	}()

	const selectQuery = `
		SELECT deleted_at
		FROM users
		WHERE id = $1
		FOR UPDATE
	`
	var deletedAt *time.Time
	err = tx.QueryRow(ctx, selectQuery, userID).Scan(&deletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrUserNotFound
		}

		return fmt.Errorf("%s: select user: %w", op, err)
	}

	if deletedAt != nil {
		return storage.ErrUserAlreadyDeleted
	}

	const updateQuery = `
		UPDATE users
		SET deleted_at = NOW()
		WHERE id = $1
	`
	res, err := tx.Exec(ctx, updateQuery, userID)
	if err != nil {
		return fmt.Errorf("%s: mark deleted: %w", op, err)
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
		UPDATE magic_links
		SET used_at = NOW()
		WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`
	if _, err := tx.Exec(ctx, invalidateMagicLinksQuery, userID); err != nil {
		return fmt.Errorf("%s: invalidate magic links: %w", op, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%s: commit: %w", op, err)
	}

	return nil
}
