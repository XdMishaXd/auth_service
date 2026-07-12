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
