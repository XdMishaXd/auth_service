package redis

import (
	"context"
	"fmt"
	"time"
)

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

func pendingKey(tokenHash string) string {
	return fmt.Sprintf("2fa:pending:%s", tokenHash)
}

func usedKey(tokenHash string) string {
	return fmt.Sprintf("2fa:used:%s", tokenHash)
}
