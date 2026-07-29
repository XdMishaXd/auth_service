package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	redisstorage "auth_service/internal/storage/redis"

	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// setupTestLimiter поднимает реальный Redis в контейнере и возвращает
// готовый Limiter поверх настоящего RedisRepo — тот же путь выполнения
// (ScriptLoad + EvalSha), что и в проде.
func setupTestLimiter(t *testing.T) *Limiter {
	t.Helper()
	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:8-alpine")
	if err != nil {
		t.Fatalf("запуск redis-контейнера: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	// connStr вида redis://host:port — RedisRepo.New хочет addr без схемы
	addr := stripRedisScheme(connStr)

	repo, err := redisstorage.New(ctx, addr, "", 0)
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() {
		_ = repo.Close(context.Background())
	})

	limiter, err := New(ctx, repo)
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	return limiter
}

func stripRedisScheme(connStr string) string {
	const prefix = "redis://"
	if len(connStr) > len(prefix) && connStr[:len(prefix)] == prefix {
		return connStr[len(prefix):]
	}
	return connStr
}

// TestLimiter_Allow_BurstNotExceeded — при burst=5 и большом Period
// (эффективно "не пополняется" за время теста) ровно 5 из N конкурентных
// запросов должны пройти, остальные — получить Allowed=false.
func TestLimiter_Allow_ConcurrentBurstRespected(t *testing.T) {
	ctx := context.Background()
	limiter := setupTestLimiter(t)

	policy := Policy{
		Burst:  5,
		Rate:   5,
		Period: time.Hour, // растянутый период — токены практически не пополняются за время теста
	}

	const goroutines = 20
	key := "test:burst:concurrent"

	var wg sync.WaitGroup
	results := make(chan Decision, goroutines)
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, err := limiter.Allow(ctx, key, policy)
			if err != nil {
				errs <- err
				return
			}
			results <- decision
		}()
	}

	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("неожиданная ошибка Allow: %v", err)
	}

	var allowed, denied int
	for d := range results {
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
	}

	if allowed != policy.Burst {
		t.Fatalf("хочу ровно %d разрешённых запросов (burst), получил %d (denied=%d)", policy.Burst, allowed, denied)
	}
	if denied != goroutines-policy.Burst {
		t.Fatalf("хочу %d отклонённых запросов, получил %d", goroutines-policy.Burst, denied)
	}
}

// TestLimiter_Allow_DifferentKeysIndependent — лимиты по разным ключам
// не должны друг на друга влиять (проверка, что key реально изолирует
// состояние в Redis, а не делится глобально).
func TestLimiter_Allow_DifferentKeysIndependent(t *testing.T) {
	ctx := context.Background()
	limiter := setupTestLimiter(t)

	policy := Policy{Burst: 2, Rate: 2, Period: time.Hour}

	// Исчерпываем лимит по ключу A
	for i := 0; i < 2; i++ {
		d, err := limiter.Allow(ctx, "key:a", policy)
		if err != nil {
			t.Fatalf("Allow key:a: %v", err)
		}
		if !d.Allowed {
			t.Fatalf("ожидал Allowed=true на попытке %d для key:a", i+1)
		}
	}

	// key:a должен быть исчерпан
	d, err := limiter.Allow(ctx, "key:a", policy)
	if err != nil {
		t.Fatalf("Allow key:a (3-я попытка): %v", err)
	}
	if d.Allowed {
		t.Fatalf("key:a должен быть исчерпан после burst, но получил Allowed=true")
	}

	// key:b — независимый лимит, должен быть свежим
	d, err = limiter.Allow(ctx, "key:b", policy)
	if err != nil {
		t.Fatalf("Allow key:b: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("key:b должен быть независим от key:a, но получил Allowed=false")
	}
}

// TestLimiter_Allow_RetryAfterPositiveWhenDenied — при отказе RetryAfter
// должен быть > 0, иначе клиент не поймёт, сколько ждать перед повтором.
func TestLimiter_Allow_RetryAfterPositiveWhenDenied(t *testing.T) {
	ctx := context.Background()
	limiter := setupTestLimiter(t)

	policy := Policy{Burst: 1, Rate: 1, Period: time.Hour}
	key := "test:retry-after"

	if _, err := limiter.Allow(ctx, key, policy); err != nil {
		t.Fatalf("первый Allow: %v", err)
	}

	d, err := limiter.Allow(ctx, key, policy)
	if err != nil {
		t.Fatalf("второй Allow: %v", err)
	}
	if d.Allowed {
		t.Fatalf("ожидал отказ на второй попытке при burst=1")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("ожидал RetryAfter > 0 при отказе, получил %v", d.RetryAfter)
	}
}
