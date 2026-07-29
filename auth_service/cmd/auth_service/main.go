package main

import (
	"context"
	"log/slog"
	"time"

	"auth_service/internal/config"
	"auth_service/logger"
)

// @title           Auth Service API
// @version         1.0
// @description     Сервис авторизации
// @host            localhost:8082
// @BasePath        /

func main() {
	cfg := config.MustLoad("./config/config.yaml")

	log := logger.MustSetup(cfg.Env)
	log.Info("starting auth service")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	app, cleanup, err := buildApp(ctx, cfg, log)
	if err != nil {
		log.Error("failed to build app", slog.String("err", err.Error()))
		return
	}
	defer cleanup(log)

	srv := newHTTPServer(cfg, app.Router.Setup())
	run(srv, cleanup, log)
}
