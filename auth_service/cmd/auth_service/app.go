package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/config"
	"auth_service/internal/rabbitmq"
	rateLimit "auth_service/internal/ratelimit"
	"auth_service/internal/router"

	"auth_service/internal/storage/postgres"
	redisClient "auth_service/internal/storage/redis"
)

type App struct {
	Postgres *postgres.Repo
	Redis    *redisClient.Repo
	RabbitMQ *rabbitmq.RabbitMQClient
	Router   *router.Router
}

// ctxCloser — ресурсы, закрывающиеся с учётом контекста
// (postgres/redis/rabbitmq не реализуют io.Closer из stdlib,
// т.к. их Close требует ctx для сетевого таймаута на закрытии).
type ctxCloser interface {
	Close(ctx context.Context) error
}

type cleanupFunc func(log *slog.Logger)

// buildApp собирает все внешние зависимости и возвращает функцию
// cleanup, закрывающую УЖЕ ОТКРЫТЫЕ на момент ошибки ресурсы —
// вызывается и на успешном пути, и через defer при ошибке в main.
func buildApp(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, cleanupFunc, error) {
	var closers []ctxCloser

	cleanup := func(log *slog.Logger) {
		closeAll(closers, log)
	}

	postgresql, err := postgres.New(ctx, cfg, log)
	if err != nil {
		return nil, cleanup, fmt.Errorf("postgres init: %w", err)
	}
	closers = append(closers, postgresql)
	log.Info("postgresql connected", //nolint:staticcheck // QF1008: селектор через встроенное поле оставлен явно для читаемости
		slog.String("host", cfg.Postgres.Host),
		slog.Int("port", cfg.Postgres.Port), //nolint:staticcheck // QF1008: селектор через встроенное поле оставлен явно для читаемости
	)

	rdb, err := redisClient.New(ctx, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.Db)
	if err != nil {
		return nil, cleanup, fmt.Errorf("redis init: %w", err)
	}
	closers = append(closers, rdb)
	log.Info("redis connected", slog.String("host", cfg.Redis.Addr))

	rabbitMQClient, err := rabbitmq.New(cfg.RabbitMQ.URL, cfg.RabbitMQ.QueueName)
	if err != nil {
		return nil, cleanup, fmt.Errorf("rabbitmq init: %w", err)
	}
	closers = append(closers, rabbitMQClient)
	log.Info("rabbitmq connected")

	limiter, err := rateLimit.New(ctx, rdb)
	if err != nil {
		return nil, cleanup, fmt.Errorf("rate limiter init: %w", err)
	}

	rtr := buildRouter(cfg, log, postgresql, rdb, rabbitMQClient, limiter)

	return &App{Postgres: postgresql, Redis: rdb, RabbitMQ: rabbitMQClient, Router: rtr}, cleanup, nil
}

// closeAll закрывает ресурсы в обратном порядке открытия (LIFO).
// closeCtx создаётся один раз здесь, а не пробрасывается снаружи —
// на момент shutdown исходный ctx из main мог быть уже отменён/истёк.
func closeAll(closers []ctxCloser, log *slog.Logger) {
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(closeCtx); err != nil {
			log.Error("failed to close resource", slog.String("err", err.Error()))
		}
	}
}
