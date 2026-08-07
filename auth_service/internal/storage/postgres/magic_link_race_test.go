package postgres

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"auth_service/internal/models"
	"auth_service/internal/storage"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// setupTestRepo поднимает реальный Postgres в контейнере, накатывает схему
// из init_table и возвращает готовый PostgresRepo поверх настоящего pool.
func setupTestRepo(t *testing.T) *Repo {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		tcpostgres.WithDatabase("auth_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("setup postgres-container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	// Накатываем схему через goose (нужен database/sql поверх pgx stdlib)
	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			t.Logf("failed to close sqlDB: %v", err)
		}
	}()

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose.SetDialect: %v", err)
	}

	migrationsDir := filepath.Join("..", "..", "..", "migrations", "init_table")
	if err := goose.Up(sqlDB, migrationsDir); err != nil {
		t.Fatalf("goose.Up: %v", err)
	}

	// Реальный pgxpool.Pool для самого репозитория — то же соединение,
	// но через боевой драйвер, которым пользуется PostgresRepo в проде.
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	return &Repo{pool: pool, log: log}
}

// seedUserAndApp вставляет минимальные строки, нужные из-за FK-constraint'ов
// magic_links (user_id, app_id).
func seedUserAndApp(ctx context.Context, t *testing.T, repo *Repo) (userID, appID int64) {
	t.Helper()

	err := repo.pool.QueryRow(ctx, `
		INSERT INTO users (email, username, password_hash, is_verified)
		VALUES ('race@test.local', 'race_user', 'x', true)
		RETURNING id
	`).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	err = repo.pool.QueryRow(ctx, `
		INSERT INTO apps (name, secret)
		VALUES ('race_app', 'race_secret')
		RETURNING id
	`).Scan(&appID)
	if err != nil {
		t.Fatalf("seed app: %v", err)
	}

	return userID, appID
}

func TestConsumeMagicLink_ConcurrentRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	repo := setupTestRepo(t)
	userID, appID := seedUserAndApp(ctx, t, repo)

	tokenHash := []byte("fixed-test-token-hash-for-race")
	link := &models.MagicLink{
		UserID:    userID,
		AppID:     int32(appID),
		TokenHash: tokenHash,
		SessionID: "race-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.SaveMagicLink(ctx, link); err != nil {
		t.Fatalf("SaveMagicLink: %v", err)
	}

	const goroutines = 20
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		successCount int
		winner       *models.MagicLink
	)

	results := make(chan error, goroutines)

	for range goroutines {
		wg.Go(func() {
			consumed, err := repo.ConsumeMagicLink(ctx, tokenHash)
			if err == nil {
				mu.Lock()
				successCount++
				winner = consumed
				mu.Unlock()
			}
			results <- err
		})
	}

	wg.Wait()
	close(results)

	for err := range results {
		switch {
		case err == nil:
		case errors.Is(err, storage.ErrMagicLinkNotFound):
			// ожидаемо для всех "проигравших" — токен уже потреблён
		default:
			t.Errorf("неожиданная ошибка: %v", err)
		}
	}

	if successCount != 1 {
		t.Fatalf("хочу ровно 1 успешное потребление из %d горутин, получил %d", goroutines, successCount)
	}

	if winner == nil {
		t.Fatal("победитель не вернул MagicLink")
	}
	if winner.UserID != userID || int64(winner.AppID) != appID || winner.SessionID != "race-session" {
		t.Fatalf("данные победителя не совпадают с сохранённым токеном: %+v", winner)
	}
}
