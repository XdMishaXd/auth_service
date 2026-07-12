package redis

import (
	"context"
	"fmt"

	"auth_service/internal/storage"
)

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
func (r *RedisRepo) ExecuteAtomicOp(ctx context.Context, opID string, keys []string, args ...any) (any, error) {
	const op = "storage.redis.ExecuteAtomicOp"

	res, err := r.client.EvalSha(ctx, opID, keys, args...).Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return res, nil
}
