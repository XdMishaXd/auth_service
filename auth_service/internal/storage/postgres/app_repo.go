package postgres

import (
	"context"
	"errors"
	"fmt"

	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/jackc/pgx/v5"
)

func (r *PostgresRepo) App(ctx context.Context, appID int32) (*models.App, error) {
	const op = "storage.postgres.App"

	query := `
		SELECT id, name, secret
		FROM apps
		WHERE id = $1;
	`

	var a models.App

	err := r.pool.QueryRow(ctx, query, appID).Scan(&a.ID, &a.Name, &a.Secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrAppNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &a, nil
}

func (r *PostgresRepo) AppSecret(ctx context.Context, appID int32) (string, error) {
	const op = "storage.postgres.AppSecret"

	query := `SELECT secret FROM apps WHERE id = $1`

	var secret string
	err := r.pool.QueryRow(ctx, query, appID).Scan(&secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", storage.ErrAppNotFound
		}

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return secret, nil
}
