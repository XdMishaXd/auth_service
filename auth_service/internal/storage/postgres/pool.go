package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepo предоставляет доступ к данным PostgreSQL.
type Repo struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// New создаёт репозиторий PostgreSQL и проверяет соединение с базой данных.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Repo, error) {
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

	return &Repo{pool: pool, log: log}, nil
}

// Close закрывает пул соединений с базой данных.
func (r *Repo) Close(ctx context.Context) error {
	const op = "storage.postgres.Close"

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
		return fmt.Errorf("%s: %w", op, ctx.Err())
	}
}

// dsn формирует строку подключения к базе данных.
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
