package redis

import (
	"context"
	"fmt"
	"time"

	"auth_service/internal/models"
	"auth_service/internal/storage"
)

// SetPendingSession создаёт pending-сессию логина после успешной проверки
// пароля/oauth, до подтверждения второго фактора.
func (r *RedisRepo) SetPendingSession(ctx context.Context, sessionID string, session models.PendingSession, ttl time.Duration) error {
	const op = "storage.redis.SetPendingSession"

	key := pendingSessionKey(sessionID)

	data := map[string]interface{}{
		"user_id":    session.UserID,
		"app_id":     session.AppID,
		"action":     string(session.Action),
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

// GetPendingSession читает pending-сессию. Не удаляет её — используется для
// сверки session_id при выпуске нового magic-link (resend) без завершения флоу.
func (r *RedisRepo) GetPendingSession(ctx context.Context, sessionID string) (*models.PendingSession, error) {
	const op = "storage.redis.GetPendingSession"

	key := pendingSessionKey(sessionID)

	res, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if len(res) == 0 {
		return nil, storage.ErrPendingSessionNotFound
	}

	session := &models.PendingSession{}
	if _, err := fmt.Sscanf(res["user_id"], "%d", &session.UserID); err != nil {
		return nil, fmt.Errorf("%s: parse user_id: %w", op, err)
	}
	if _, err := fmt.Sscanf(res["app_id"], "%d", &session.AppID); err != nil {
		return nil, fmt.Errorf("%s: parse app_id: %w", op, err)
	}
	action, ok := res["action"]
	if !ok || action == "" {
		return nil, fmt.Errorf("%s: pending session missing action: %w", op, storage.ErrPendingSessionNotFound)
	}
	session.Action = models.Action(action)

	return session, nil
}

// DeletePendingSession завершает pending-сессию — вызывается один раз, сразу
// после успешного ConsumeMagicLink в Postgres, чтобы тот же session_id нельзя
// было переиспользовать повторно даже в рамках оставшегося TTL.
func (r *RedisRepo) DeletePendingSession(ctx context.Context, sessionID string) error {
	const op = "storage.redis.DeletePendingSession"

	if err := r.client.Del(ctx, pendingSessionKey(sessionID)).Err(); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func pendingSessionKey(sessionID string) string {
	return fmt.Sprintf("2fa:pending_session:%s", sessionID)
}
