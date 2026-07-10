package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/config"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepo struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*PostgresRepo, error) {
	const op = "storage.postgres.New"

	dsn := dsn(cfg)

	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse config: %w", op, err)
	}

	poolConfig.MaxConns = 10
	poolConfig.MinConns = 2
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = time.Minute * 30

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create pool: %w", op, err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%s: failed to ping database: %w", op, err)
	}

	return &PostgresRepo{pool: pool, log: log}, nil
}

func (r *PostgresRepo) SaveUser(ctx context.Context, email, username string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"

	query := `
		INSERT INTO users (email, username, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id;
	`

	var id int64

	err := r.pool.QueryRow(ctx, query, email, username, string(passHash)).Scan(&id)
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
	query := `
		SELECT id, email, username, password_hash, is_verified
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
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrUserNotFound
		}

		return nil, err
	}

	return &u, err
}

func (r *PostgresRepo) UserByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, email, username, password_hash, is_verified
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
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, storage.ErrUserNotFound
	}

	return &u, err
}

func (r *PostgresRepo) UserByEmail(ctx context.Context, email string) (int64, error) {
	query := `
		SELECT id
		FROM users
		WHERE email = $1;
	`

	row := r.pool.QueryRow(ctx, query, email)

	var u models.User
	err := row.Scan(&u.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1, storage.ErrUserNotFound
	}

	return u.ID, err
}

// * CheckIfUserVerified проверяет, подтвердил ли пользователь свой email
func (r *PostgresRepo) CheckIfUserVerified(ctx context.Context, email string) (int64, bool, error) {
	query := `	
		SELECT id, is_verified
		FROM users
		WHERE email = $1;
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

		return 0, false, err
	}

	return id, isVerified, nil
}

func (r *PostgresRepo) SetEmailVerified(ctx context.Context, userID int64) error {
	query := `UPDATE users SET is_verified = TRUE WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, userID)

	return err
}

func (r *PostgresRepo) SaveRefreshToken(
	ctx context.Context,
	id string,
	userID int64,
	appID int32,
	tokenHash []byte,
	expiresAt time.Time,
) error {
	const query = `
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

	return err
}

func (r *PostgresRepo) UpdateRefreshToken(
	ctx context.Context,
	id uuid.UUID,
	newTokenHash []byte,
	oldTokenHash []byte,
	expiresAt time.Time,
) error {
	const query = `
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
		return err
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
	const query = `
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

		return nil, err
	}

	return &rt, nil
}

func (r *PostgresRepo) DeleteRefreshToken(
	ctx context.Context,
	id uuid.UUID,
) error {
	const query = `
		DELETE FROM refresh_tokens
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *PostgresRepo) App(ctx context.Context, appID int32) (*models.App, error) {
	query := `
		SELECT id, name, secret
		FROM apps
		WHERE id = $1;
	`

	var a models.App

	err := r.pool.QueryRow(ctx, query, appID).Scan(&a.ID, &a.Name, &a.Secret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, storage.ErrAppNotFound
	}

	return &a, err
}

func (r *PostgresRepo) SaveResetToken(
	ctx context.Context,
	tokenID uuid.UUID,
	userID int64,
	tokenHash []byte,
	expiresAt time.Time,
) error {
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

	return err
}

func (r *PostgresRepo) ResetTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.ResetToken, error) {
	const query = `
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

	// Шаг 1: атомарно занимаем токен — только один конкурентный вызов пройдёт это условие
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
func (r *PostgresRepo) MagicLinkByTokenHash(ctx context.Context, tokenHash string) (*models.MagicLink, error) {
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
			return nil, fmt.Errorf("%s: magic link not found", op)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return link, nil
}

// MarkMagicLinkAsUsed помечает magic link как использованный
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

func (r *PostgresRepo) Close(ctx context.Context) error {
	done := make(chan struct{})

	go func() {
		r.pool.Close()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		r.log.Error("postgres pool close timed out, connections may leak")
		return ctx.Err()
	}
}

// * dsn формирует конфигурацию базы данных.
func dsn(cfg *config.Config) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=%s",
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.DBName,
		cfg.Postgres.SSLMode,
	)
}
