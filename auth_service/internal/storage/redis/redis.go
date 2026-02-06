package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	client *redis.Client
}

func New(ctx context.Context, addr, pass string, db int) (*RedisRepo, error) {
	const op = "storage.redis.New"

	client := redis.NewClient(&redis.Options{
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

// *  SetMagicLinkPending сохраняет информацию о созданном токене
func (r *RedisRepo) SetMagicLinkPending(ctx context.Context, tokenHash string, userID int64, appID int32, ttl time.Duration) error {
	const op = "storage.redis.SetMagicLinkPending"

	key := fmt.Sprintf("2fa:pending:%s", tokenHash)

	data := map[string]interface{}{
		"user_id":    userID,
		"app_id":     appID,
		"created_at": time.Now().Unix(),
	}

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * DeleteMagicLinkPending удаляет информацию о pending токене
func (r *RedisRepo) DeleteMagicLinkPending(ctx context.Context, tokenHash string) error {
	const op = "storage.redis.DeleteMagicLinkPending"

	key := fmt.Sprintf("2fa:pending:%s", tokenHash)

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * InvalidateMagicLinksByHashes инвалидирует все токены по списку хешей
func (r *RedisRepo) InvalidateMagicLinksByHashes(ctx context.Context, tokenHashes []string, ttl time.Duration) error {
	const op = "storage.redis.InvalidateMagicLinksByHashes"

	if len(tokenHashes) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()

	for _, hash := range tokenHashes {
		usedKey := fmt.Sprintf("2fa:used:%s", hash)
		pendingKey := fmt.Sprintf("2fa:pending:%s", hash)

		pipe.Set(ctx, usedKey, "invalidated", ttl)
		pipe.Del(ctx, pendingKey)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * MarkMagicLinkAsUsed помечает токен как использованный (атомарно через SETNX)
// Возвращает true если токен был использован первый раз
// Возвращает false если токен уже был использован ранее
func (r *RedisRepo) MarkMagicLinkAsUsed(ctx context.Context, tokenHash string, ttl time.Duration) (bool, error) {
	const op = "storage.redis.MarkMagicLinkAsUsed"

	key := fmt.Sprintf("2fa:used:%s", tokenHash)

	// SETNX - атомарная операция (rate limiter на 1 запрос)
	success, err := r.client.SetNX(ctx, key, "used", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return success, nil
}

// * Close закрывает соединение с базой данных.
func (r *RedisRepo) Close() {
	r.client.Close()
}
