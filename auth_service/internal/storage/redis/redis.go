package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	client *redis.Client
}

func New(ctx context.Context, address string, db int) (*RedisRepo, error) {
	const op = "storage.redis.New"

	rdb := redis.NewClient(&redis.Options{
		Addr: address,
		// Password: password,
		DB: db,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &RedisRepo{
		client: rdb,
	}, nil
}
