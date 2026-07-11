package rateLimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth_service/internal/storage/redis"
)

// ErrRateLimited возвращать наружу не нужно отдельным типом — Decision.Allowed
// уже несёт эту информацию без ошибки. Ошибка — только про инфраструктурный отказ.
var (
	ErrRedisUnavailable = errors.New("ratelimiter: redis unavailable")
	ErrLimitExeeded     = errors.New("limit exeeded")
)

type Redis interface {
	RegisterAtomicOp(ctx context.Context) (string, error)
	ExecuteAtomicOp(ctx context.Context, opID string, keys []string, args ...any) (any, error)
}

// Policy описывает лимит для конкретного эндпоинта/типа ключа.
// Rate — сколько запросов допускается за Period в устойчивом режиме,
// Burst — сколько запросов можно сделать одномоментно сверх устойчивой скорости.
type Policy struct {
	Burst  int
	Rate   int
	Period time.Duration
}

// Decision — результат проверки лимита.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Remaining  int
}

// Limiter — потокобезопасный rate limiter поверх AtomicOpRunner.
// Один экземпляр переиспользуется на весь процесс (операция регистрируется
// один раз в New, повторная регистрация происходит лениво при NOSCRIPT).
type Limiter struct {
	redis *redis.RedisRepo
	opID  string
}

func (p Policy) ratePerSecond() float64 {
	return float64(p.Rate) / p.Period.Seconds()
}

// Validate проверяет корректность policy до использования —
// нулевой Period или Rate уронит скрипт делением на ноль внутри Lua,
// лучше поймать это на старте сервиса, а не в рантайме на первом запросе.
func (p Policy) Validate() error {
	if p.Rate <= 0 {
		return fmt.Errorf("ratelimiter: policy.Rate must be > 0, got %d", p.Rate)
	}
	if p.Period <= 0 {
		return fmt.Errorf("ratelimiter: policy.Period must be > 0, got %s", p.Period)
	}
	if p.Burst < 0 {
		return fmt.Errorf("ratelimiter: policy.Burst must be >= 0, got %d", p.Burst)
	}
	return nil
}

// New создаёт Limiter и сразу регистрирует атомарную операцию (GCRA).
// Требует живого redis на старте — сервис должен упасть при старте,
// если Redis недоступен, а не молча деградировать позже без объяснимой причины.
func New(ctx context.Context, r *redis.RedisRepo) (*Limiter, error) {
	if r == nil {
		return nil, fmt.Errorf("ratelimiter: redis repo is nil")
	}

	opID, err := r.RegisterAtomicOp(ctx)
	if err != nil {
		return nil, fmt.Errorf("ratelimiter: failed to register script: %w", err)
	}

	return &Limiter{redis: r, opID: opID}, nil
}

// Allow атомарно проверяет и расходует один токен по ключу key согласно policy.
func (l *Limiter) Allow(ctx context.Context, key string, policy Policy) (Decision, error) {
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}

	now := time.Now().UnixMilli()

	res, err := l.redis.ExecuteAtomicOp(ctx, l.opID, []string{key},
		policy.Burst,
		policy.ratePerSecond(),
		1,
		now,
	)
	if err != nil {
		if isNoScript(err) {
			opID, regErr := l.redis.RegisterAtomicOp(ctx)
			if regErr != nil {
				return Decision{}, fmt.Errorf("%w: script re-registration failed: %v", ErrRedisUnavailable, regErr)
			}
			l.opID = opID

			res, err = l.redis.ExecuteAtomicOp(ctx, l.opID, []string{key},
				policy.Burst,
				policy.ratePerSecond(),
				1,
				now,
			)
		}

		if err != nil {
			if isConnIssue(ctx, err) {
				return Decision{}, fmt.Errorf("%w: %v", ErrRedisUnavailable, err)
			}
			return Decision{}, fmt.Errorf("ratelimiter: execute failed: %w", err)
		}
	}

	return parseResult(res)
}

func parseResult(res any) (Decision, error) {
	vals, ok := res.([]interface{})
	if !ok || len(vals) != 3 {
		return Decision{}, fmt.Errorf("ratelimiter: unexpected result shape: %#v", res)
	}

	allowed, err := toInt64(vals[0])
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimiter: parsing 'allowed': %w", err)
	}
	retryAfterMS, err := toInt64(vals[1])
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimiter: parsing 'retry_after': %w", err)
	}
	remaining, err := toInt64(vals[2])
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimiter: parsing 'remaining': %w", err)
	}

	return Decision{
		Allowed:    allowed == 1,
		RetryAfter: time.Duration(retryAfterMS) * time.Millisecond,
		Remaining:  int(remaining),
	}, nil
}

func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("unexpected numeric type %T", v)
	}
}

func BuildKey(endpoint, keyType, identifier string) string {
	h := sha256.Sum256([]byte(identifier))
	return fmt.Sprintf("ratelimit:%s:%s:%s", endpoint, keyType, hex.EncodeToString(h[:8]))
}

func isNoScript(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "NOSCRIPT")
}

func isConnIssue(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connect: ") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF")
}
