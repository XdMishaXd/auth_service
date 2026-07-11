package redis

import (
	"context"
	"fmt"
	"time"

	"auth_service/internal/storage"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	client *redis.Client
}

func New(ctx context.Context, addr, pass string, db int) (*RedisRepo, error) {
	const op = "storage.redis.New"

	client := redis.NewClient(
		&redis.Options{
			Addr:         addr,
			Password:     pass,
			DB:           db,
			MaxRetries:   3,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     10,
			MinIdleConns: 2,
		})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &RedisRepo{
		client: client,
	}, nil
}

// RegisterAtomicOp регистрирует атомарную операцию (Lua-скрипт) в Redis
// и возвращает её идентификатор для последующих вызовов через ExecuteAtomicOp.
func (r *RedisRepo) RegisterAtomicOp(ctx context.Context) (string, error) {
	const op = "storage.redis.RegisterAtomicOp"

	sha, err := r.client.ScriptLoad(ctx, storage.GCRAScript).Result()
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return sha, nil
}

// ExecuteAtomicOp выполняет ранее зарегистрированную атомарную операцию по её id.
func (r *RedisRepo) ExecuteAtomicOp(ctx context.Context, opID string, keys []string, args ...interface{}) (interface{}, error) {
	const op = "storage.redis.ExecuteAtomicOp"

	res, err := r.client.EvalSha(ctx, opID, keys, args...).Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return res, nil
}

// SetMagicLinkPending сохраняет информацию о созданном токене.
// Используется как anti-replay слой поверх Postgres (источника истины).
func (r *RedisRepo) SetMagicLinkPending(ctx context.Context, tokenHash string, userID int64, appID int32, ttl time.Duration) error {
	const op = "storage.redis.SetMagicLinkPending"

	key := pendingKey(tokenHash)

	data := map[string]interface{}{
		"user_id":    userID,
		"app_id":     appID,
		"created_at": time.Now().Unix(),
	}

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// DeleteMagicLinkPending удаляет информацию о pending токене
func (r *RedisRepo) DeleteMagicLinkPending(ctx context.Context, tokenHash string) error {
	const op = "storage.redis.DeleteMagicLinkPending"

	key := pendingKey(tokenHash)

	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// MarkMagicLinkAsUsed атомарно помечает токен как использованный (SETNX).
// Возвращает true, если токен помечен впервые этим вызовом.
// Возвращает false, если ключ уже существовал (replay-попытка или уже инвалидирован).
//
// ВАЖНО: это только anti-replay слой. Источником истины остаётся Postgres —
// даже если этот метод вернул true, вызывающий код обязан дополнительно
// проверить link.Used / link.ExpiresAt в Postgres, прежде чем выдавать сессию.
func (r *RedisRepo) MarkMagicLinkAsUsed(ctx context.Context, tokenHash string, ttl time.Duration) (bool, error) {
	const op = "storage.redis.MarkMagicLinkAsUsed"

	key := usedKey(tokenHash)

	success, err := r.client.SetNX(ctx, key, "used", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return success, nil
}

// IsMagicLinkUsed проверяет, помечен ли токен использованным/инвалидированным в Redis.
// Не заменяет проверку MarkMagicLinkAsUsed — полезен для быстрого read-only чека
// (например, до похода в Postgres), но не для атомарного списания токена.
func (r *RedisRepo) IsMagicLinkUsed(ctx context.Context, tokenHash string) (bool, error) {
	const op = "storage.redis.IsMagicLinkUsed"

	key := usedKey(tokenHash)

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return exists > 0, nil
}

// InvalidateMagicLinksByHashes инвалидирует список токенов в Redis:
// - ставит "used"-метку, чтобы MarkMagicLinkAsUsed для них больше не проходил
// - удаляет pending-запись, если она была
//
// Вызывается синхронно с PostgresRepo.InvalidateMagicLinksByUserID,
// чтобы оба хранилища не расходились по состоянию.
func (r *RedisRepo) InvalidateMagicLinksByHashes(ctx context.Context, tokenHashes []string, ttl time.Duration) error {
	const op = "storage.redis.InvalidateMagicLinksByHashes"

	if len(tokenHashes) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	for _, hash := range tokenHashes {
		pipe.Set(ctx, usedKey(hash), "invalidated", ttl)
		pipe.Del(ctx, pendingKey(hash))
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Close закрывает соединение с Redis.
func (r *RedisRepo) Close(ctx context.Context) error {
	const op = "storage.redis.Close"

	done := make(chan error, 1)
	go func() {
		done <- r.client.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", op, ctx.Err())
	}
}

func pendingKey(tokenHash string) string {
	return fmt.Sprintf("2fa:pending:%s", tokenHash)
}

func usedKey(tokenHash string) string {
	return fmt.Sprintf("2fa:used:%s", tokenHash)
}
