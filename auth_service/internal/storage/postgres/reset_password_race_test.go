package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"auth_service/internal/storage"

	"github.com/google/uuid"
)

// seedResetToken вставляет активный reset-токен для существующего пользователя.
func seedResetToken(t *testing.T, ctx context.Context, repo *PostgresRepo, userID int64) uuid.UUID {
	t.Helper()

	tokenID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7: %v", err)
	}

	if err := repo.SaveResetToken(ctx, tokenID, userID, []byte("fixed-reset-token-hash"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("seed reset token: %v", err)
	}

	return tokenID
}

func TestResetPassword_ConcurrentRace(t *testing.T) {
	ctx := context.Background()
	repo := setupTestRepo(t) // переиспользуем helper из magic_link_race_test.go

	userID, _ := seedUserAndApp(t, ctx, repo)
	tokenID := seedResetToken(t, ctx, repo, userID)

	const goroutines = 20
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		successCount int
		winnerHash   []byte
	)

	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			newHash := []byte(fmt.Sprintf("new-password-hash-%d", i))
			err := repo.ResetPassword(ctx, userID, tokenID, newHash)

			if err == nil {
				mu.Lock()
				successCount++
				winnerHash = newHash
				mu.Unlock()
			}

			results <- err
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		if err != nil && !errors.Is(err, storage.ErrResetTokenUsed) {
			t.Errorf("неожиданная ошибка: %v", err)
		}
	}

	if successCount != 1 {
		t.Fatalf("хочу ровно 1 успешный сброс пароля из %d горутин, получил %d", goroutines, successCount)
	}

	// Проверяем, что реально применился именно хэш от единственного победителя,
	// а не от кого-то из "проигравших" (защита от гонки на этапе UPDATE users).
	var actualHash []byte
	err := repo.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&actualHash)
	if err != nil {
		t.Fatalf("проверка password_hash: %v", err)
	}
	if string(actualHash) != string(winnerHash) {
		t.Fatalf("password_hash в БД не совпадает с хэшем победителя: хочу %q, получил %q", winnerHash, actualHash)
	}

	// Побочные эффекты транзакции — тоже часть контракта ResetPassword.
	var refreshCount, resetTokenCount int
	if err := repo.pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, userID).Scan(&refreshCount); err != nil {
		t.Fatalf("count refresh_tokens: %v", err)
	}
	if refreshCount != 0 {
		t.Errorf("refresh_tokens должны быть удалены, осталось: %d", refreshCount)
	}

	if err := repo.pool.QueryRow(ctx, `SELECT count(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&resetTokenCount); err != nil {
		t.Fatalf("count password_reset_tokens: %v", err)
	}
	if resetTokenCount != 0 {
		t.Errorf("password_reset_tokens должны быть удалены, осталось: %d", resetTokenCount)
	}
}
