package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"

	"auth_service/internal/storage"
)

// seedOAuthOnlyUser создаёт пользователя без пароля с двумя привязанными
// провайдерами — минимальный набор, при котором действует защита
// "нельзя отвязать последний способ входа".
func seedOAuthOnlyUser(t *testing.T, ctx context.Context, repo *PostgresRepo) int64 {
	t.Helper()

	var userID int64
	err := repo.pool.QueryRow(ctx, `
		INSERT INTO users (email, username, password_hash, is_verified)
		VALUES ('oauth-race@test.local', 'oauth_race_user', NULL, true)
		RETURNING id
	`).Scan(&userID)
	if err != nil {
		t.Fatalf("seed oauth-only user: %v", err)
	}

	for _, provider := range []string{"google", "github"} {
		err := repo.SaveOAuthAccount(ctx, userID, provider, provider+"-provider-id", "oauth-race@test.local")
		if err != nil {
			t.Fatalf("seed oauth account %s: %v", provider, err)
		}
	}

	return userID
}

// TestUnlinkOAuthAccount_ConcurrentRace проверяет, что FOR UPDATE
// сериализует конкурентные unlink-запросы: у пользователя без пароля есть
// ровно 2 провайдера, обе горутины одновременно пытаются отвязать
// РАЗНЫЕ провайдеры. Без блокировки строки обе могли бы одновременно
// прочитать "остался 1 провайдер" и обе пройти проверку — тогда
// пользователь остался бы вообще без способа входа. С FOR UPDATE вторая
// транзакция обязана дождаться первой и увидеть актуальное состояние.
func TestUnlinkOAuthAccount_ConcurrentRace(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepo(t)

	userID := seedOAuthOnlyUser(t, ctx, repo)

	providers := []string{"google", "github"}
	var wg sync.WaitGroup
	results := make(chan error, len(providers))

	for _, provider := range providers {
		provider := provider
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := repo.UnlinkOAuthAccount(ctx, userID, provider)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	var successCount, lastAuthMethodCount int
	for err := range results {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, storage.ErrOAuthLastAuthMethod):
			lastAuthMethodCount++
		default:
			t.Errorf("неожиданная ошибка: %v", err)
		}
	}

	if successCount != 1 {
		t.Fatalf("хочу ровно 1 успешный unlink, получил %d", successCount)
	}
	if lastAuthMethodCount != 1 {
		t.Fatalf("хочу ровно 1 отказ ErrOAuthLastAuthMethod, получил %d", lastAuthMethodCount)
	}

	// Финальная проверка состояния — у пользователя должен остаться
	// РОВНО один провайдер, ни ноль (потеря доступа), ни два (гонка не
	// сработала и обе транзакции прошли).
	var remaining int
	err := repo.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1`, userID).Scan(&remaining)
	if err != nil {
		t.Fatalf("count remaining accounts: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("хочу ровно 1 оставшийся провайдер, получил %d — это либо потеря доступа (0), либо гонка не защитилась (2)", remaining)
	}
}

// TestUnlinkOAuthAccount_WithPassword_ConcurrentDelete — контрольный
// сценарий: у пользователя есть пароль, значит защита "последний способ
// входа" не действует (hasPassword == true пропускает проверку remaining).
// Обе конкурентные попытки unlink должны пройти успешно без дедлоков.
func TestUnlinkOAuthAccount_WithPassword_ConcurrentDelete(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepo(t)

	var userID int64
	err := repo.pool.QueryRow(ctx, `
		INSERT INTO users (email, username, password_hash, is_verified)
		VALUES ('oauth-race-pw@test.local', 'oauth_race_pw_user', 'some-hash', true)
		RETURNING id
	`).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user with password: %v", err)
	}

	providers := []string{"google", "github"}
	for _, provider := range providers {
		if err := repo.SaveOAuthAccount(ctx, userID, provider, provider+"-provider-id", "oauth-race-pw@test.local"); err != nil {
			t.Fatalf("seed oauth account %s: %v", provider, err)
		}
	}

	var wg sync.WaitGroup
	results := make(chan error, len(providers))

	for _, provider := range providers {
		provider := provider
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- repo.UnlinkOAuthAccount(ctx, userID, provider)
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Errorf("неожиданная ошибка при наличии пароля: %v", err)
		}
	}

	var remaining int
	if err := repo.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1`, userID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining accounts: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("хочу 0 оставшихся провайдеров (оба unlink должны пройти), получил %d", remaining)
	}
}
