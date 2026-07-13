package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth_service/internal/auth/oauth"
	"auth_service/internal/storage"

	"github.com/redis/go-redis/v9"
)

const oauthStatePrefix = "oauth_state:"

// SaveOAuthState сохраняет одноразовый state-токен с TTL.
func (r *RedisRepo) SaveOAuthState(
	ctx context.Context,
	state string,
	payload oauth.OAuthStatePayload,
	ttl time.Duration,
) error {
	const op = "storage.redis.SaveOAuthState"

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s: marshal payload: %w", op, err)
	}

	key := oauthStatePrefix + state

	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// GetAndDeleteOAuthState атомарно читает и удаляет state-токен (GETDEL).
func (r *RedisRepo) GetAndDeleteOAuthState(
	ctx context.Context,
	state string,
) (*oauth.OAuthStatePayload, error) {
	const op = "storage.redis.GetAndDeleteOAuthState"

	key := oauthStatePrefix + state

	data, err := r.client.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, storage.ErrOAuthStateNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var payload oauth.OAuthStatePayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, fmt.Errorf("%s: unmarshal payload: %w", op, err)
	}

	return &payload, nil
}
