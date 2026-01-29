package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_service/internal/auth"
	"auth_service/internal/config"
	"auth_service/internal/http_server/handlers/login"
	"auth_service/internal/http_server/handlers/logout"
	"auth_service/internal/http_server/handlers/refresh"
	register "auth_service/internal/http_server/handlers/register"
	resendEmail "auth_service/internal/http_server/handlers/resend_verification_email"
	"auth_service/internal/http_server/handlers/verify"
	rateLimit "auth_service/internal/middleware/ratelimit"
	swaggerAuth "auth_service/internal/middleware/swagger-auth"
	"auth_service/internal/rabbitmq"
	"auth_service/internal/storage/postgres"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-playground/validator/v10"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title           Auth Service API
// @version         1.0
// @description     Сервис авторизации
// @host            localhost:8082
// @BasePath        /

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad("./config/config.yaml")

	log := setupLogger(cfg.Env)

	log.Info("starting auth service", slog.String("env", cfg.Env))

	// * Context для инициализации компонентов
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	storage, err := postgres.New(ctx, cfg)
	if err != nil {
		log.Error("failed to connect postgres", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer storage.Close()

	log.Info("postgresql connected successfully",
		slog.String("host", cfg.Postgres.Host),
		slog.Int("port", cfg.Postgres.Port),
		slog.String("database", cfg.Postgres.DBName),
	)

	rabbitMQClient, err := rabbitmq.New(cfg.RabbitMQ.URL, cfg.RabbitMQ.QueueName)
	if err != nil {
		log.Error("failed to connect rabbitmq", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer rabbitMQClient.Close()

	log.Info("rabbitmq connected successfully")

	authMiddleware := auth.New(
		log,
		storage,
		storage,
		storage,
		cfg.Tokens.AccessTokenTTL,
		cfg.Tokens.RefreshTokenTTL,
	)

	requestValidator := validator.New()

	router := setupRouter(
		log,
		cfg,
		requestValidator,
		authMiddleware,
		rabbitMQClient,
	)

	srv := &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Info("starting http server", slog.String("address", cfg.HTTPServer.Address))
		serverErrors <- srv.ListenAndServe()
	}()

	// * graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)

	case sig := <-shutdown:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))

		cancel()

		// * Graceful shutdown context
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		log.Info("shutting down http server")

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("failed to shutdown server gracefully", slog.String("error", err.Error()))

			if closeErr := srv.Close(); closeErr != nil {
				log.Error("failed to force close server", slog.String("error", closeErr.Error()))
			}
		}

		log.Info("server stopped gracefully")
	}
}

func setupRouter(
	log *slog.Logger,
	cfg *config.Config,
	validate *validator.Validate,
	authService *auth.Auth,
	msgBroker *rabbitmq.RabbitMQClient,
) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	if cfg.Swagger.Enabled {
		r.Group(func(r chi.Router) {
			r.Use(swaggerAuth.New(cfg.Swagger.Username, cfg.Swagger.Password))
			r.Get("/swagger/*", httpSwagger.WrapHandler)
		})
	}

	r.Route("/auth", func(r chi.Router) {
		r.With(rateLimit.Register()).Post("/register",
			register.New(
				log,
				validate,
				authService,
				msgBroker,
				cfg.Tokens.VerificationTokenTTL,
				cfg.Tokens.VerificationTokenSecret,
				cfg.HTTPServer.Address,
			),
		)
		r.With(rateLimit.Login()).Post("/login",
			login.New(log, validate, authService),
		)
		r.With(rateLimit.Refresh()).Post("/refresh",
			refresh.New(log, validate, authService),
		)
		r.With(rateLimit.Logout()).Post("/logout",
			logout.New(log, validate, authService),
		)
		r.With(rateLimit.Verify()).Get("/verify",
			verify.New(log, authService, cfg.Tokens.VerificationTokenSecret),
		)
		r.With(rateLimit.ResendVerificationEmail()).Post("/verify/resend",
			resendEmail.New(
				log,
				validate,
				authService,
				msgBroker,
				cfg.Tokens.VerificationTokenTTL,
				cfg.Tokens.VerificationTokenSecret,
				cfg.HTTPServer.Address,
			),
		)
	})

	return r
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
