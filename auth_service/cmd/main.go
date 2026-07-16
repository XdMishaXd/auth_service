package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_service/internal/auth"
	twoFactorAuth "auth_service/internal/auth/2fa"
	"auth_service/internal/auth/oauth"
	"auth_service/internal/auth/oauth/providers"
	"auth_service/internal/config"
	"auth_service/internal/http_server/handlers/health"
	"auth_service/internal/http_server/handlers/login"
	"auth_service/internal/http_server/handlers/logout"
	"auth_service/internal/http_server/handlers/oauth/accounts"
	"auth_service/internal/http_server/handlers/oauth/callback"
	"auth_service/internal/http_server/handlers/oauth/link"
	ologin "auth_service/internal/http_server/handlers/oauth/login"
	"auth_service/internal/http_server/handlers/oauth/unlink"
	"auth_service/internal/http_server/handlers/password/forgot"
	"auth_service/internal/http_server/handlers/password/reset"
	"auth_service/internal/http_server/handlers/refresh"
	register "auth_service/internal/http_server/handlers/register"
	resendEmail "auth_service/internal/http_server/handlers/resend_verification_email"
	"auth_service/internal/http_server/handlers/verify"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	httpRateLimit "auth_service/internal/http_server/middleware/rate_limiter"
	swaggerAuth "auth_service/internal/http_server/middleware/swagger-auth"
	"auth_service/internal/lib/jwt"
	customValidator "auth_service/internal/lib/validation/custom_validator"
	"auth_service/internal/rabbitmq"
	rateLimit "auth_service/internal/ratelimit"
	"auth_service/internal/storage/postgres"
	"auth_service/internal/storage/redis"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-playground/validator/v10"
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/sync/errgroup"
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

	googleProvider := providers.NewGoogleProvider(
		cfg.OAuth.Google.ClientID,
		cfg.OAuth.Google.ClientSecret,
		cfg.OAuth.Google.RedirectURL,
	)

	githubProvider := providers.NewGitHubProvider(
		cfg.OAuth.GitHub.ClientID,
		cfg.OAuth.GitHub.ClientSecret,
		cfg.OAuth.GitHub.RedirectURL,
	)

	oauthProviders := map[string]oauth.OAuthProvider{
		"google": googleProvider,
		"github": githubProvider,
	}

	log := setupLogger(cfg.Env)

	log.Info("starting auth service", slog.String("env", cfg.Env))

	// * Context для инициализации компонентов
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	postgresql, err := postgres.New(ctx, cfg, log)
	if err != nil {
		log.Error("failed to connect postgres", slog.String("err", err.Error()))
		os.Exit(1)
	}

	log.Info("postgresql connected successfully",
		slog.String("host", cfg.Postgres.Host),
		slog.Int("port", cfg.Postgres.Port),
		slog.String("database", cfg.Postgres.DBName),
	)

	redis, err := redis.New(ctx, cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.Db)
	if err != nil {
		log.Error("failed to connect redis", slog.String("err", err.Error()))
		os.Exit(1)
	}

	log.Info("redis connected successfully",
		slog.String("host", cfg.Redis.Addr),
		slog.Int("database", cfg.Redis.Db),
	)

	rabbitMQClient, err := rabbitmq.New(cfg.RabbitMQ.URL, cfg.RabbitMQ.QueueName)
	if err != nil {
		log.Error("failed to connect rabbitmq", slog.String("err", err.Error()))
		os.Exit(1)
	}

	log.Info("rabbitmq connected successfully")

	limiter, err := rateLimit.New(ctx, redis)
	if err != nil {
		log.Error("failed to init rate limiter", slog.String("err", err.Error()))
		os.Exit(1)
	}

	rlMiddlewares := httpRateLimit.New(limiter, log)

	twoFactorAuthService := twoFactorAuth.New(
		postgresql,
		redis,
		rabbitMQClient,
		log,
		cfg,
	)

	authService := auth.New(
		log,
		postgresql,
		postgresql,
		postgresql,
		twoFactorAuthService,
		cfg.Tokens.AccessTokenTTL,
		cfg.Tokens.RefreshTokenTTL,
		cfg.Tokens.ResetTokenTTL,
	)

	oauthService := oauth.New(
		authService,
		log,
		postgresql,
		redis,
		oauthProviders,
		cfg.OAuth.StateTTL,
	)

	requestValidator := customValidator.New()

	router := setupRouter(
		log,
		cfg,
		requestValidator,
		rlMiddlewares,
		authService,
		oauthService,
		postgresql,
		rabbitMQClient,
		allowedRedirectHostSet(cfg.OAuth.AllowedRedirectHosts),
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

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()

		var eg errgroup.Group

		eg.Go(func() error {
			if err := postgresql.Close(closeCtx); err != nil {
				return fmt.Errorf("postgres close: %w", err)
			}
			return nil
		})

		eg.Go(func() error {
			if err := rabbitMQClient.Close(closeCtx); err != nil {
				return fmt.Errorf("rabbitmq close: %w", err)
			}
			return nil
		})

		eg.Go(func() error {
			if err := redis.Close(closeCtx); err != nil {
				return fmt.Errorf("redis close: %w", err)
			}

			return nil
		})

		if err := eg.Wait(); err != nil {
			log.Error("failed to close resources gracefully", slog.String("err", err.Error()))
		}

		log.Info("server stopped gracefully")
	}
}

func setupRouter(
	log *slog.Logger,
	cfg *config.Config,
	validate *validator.Validate,
	rateLimiter *httpRateLimit.RateLimit,
	authService *auth.Auth,
	oauthService *oauth.OAuthService,
	appProvider jwt.AppSecretProvider,
	msgBroker *rabbitmq.RabbitMQClient,
	allowedRedirectHosts map[string]bool,
) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Инфраструктурный эндпоинт
	r.Get("/health", health.New())

	if cfg.Swagger.Enabled {
		r.Group(func(r chi.Router) {
			r.Use(swaggerAuth.New(cfg.Swagger.Username, cfg.Swagger.Password))
			r.Get("/swagger/*", httpSwagger.WrapHandler)
		})
	}

	r.Route("/auth", func(r chi.Router) {
		r.With(rateLimiter.Register()).Post("/register",
			register.New(
				log,
				validate,
				authService,
				msgBroker,
				cfg.Tokens.VerificationTokenTTL,
				cfg.Tokens.VerificationTokenSecret,
				cfg.HTTPServer.Address,
				cfg.HTTPServer.HandlersTimeout,
			),
		)
		r.With(rateLimiter.Login()).Post("/login",
			login.New(
				log,
				validate,
				authService,
				cfg.HTTPServer.HandlersTimeout,
				cfg.TwoFactorAuth.PendingSessionTTL,
			),
		)
		r.With(rateLimiter.Refresh()).Post("/refresh",
			refresh.New(log, validate, authService, cfg.HTTPServer.HandlersTimeout),
		)
		r.With(rateLimiter.Logout()).Post("/logout",
			logout.New(log, validate, authService, cfg.HTTPServer.HandlersTimeout),
		)
		r.With(rateLimiter.Verify()).Get("/verify",
			verify.New(
				log,
				authService,
				cfg.Tokens.VerificationTokenSecret,
				cfg.HTTPServer.HandlersTimeout,
			),
		)
		r.With(rateLimiter.ResendVerificationEmail()).Post("/verify/resend",
			resendEmail.New(
				log,
				validate,
				authService,
				msgBroker,
				cfg.Tokens.VerificationTokenTTL,
				cfg.Tokens.VerificationTokenSecret,
				cfg.HTTPServer.Address,
				cfg.HTTPServer.HandlersTimeout,
			),
		)

		r.With(rateLimiter.ForgotPassword()).Post("/password/forgot",
			forgot.New(
				log,
				validate,
				msgBroker,
				authService,
				cfg.HTTPServer.Address,
				cfg.HTTPServer.HandlersTimeout,
			),
		)

		r.With(rateLimiter.ResetPassword()).Post("/password/reset",
			reset.New(
				log,
				validate,
				authService,
				cfg.HTTPServer.HandlersTimeout,
			),
		)

		r.Route("/oauth", func(r chi.Router) {
			// Публичные эндпоинты — юзер ещё не аутентифицирован.
			r.With(rateLimiter.OAuthLogin()).Get("/{provider}/login",
				ologin.New(
					log,
					oauthService,
					allowedRedirectHosts,
				),
			)
			r.With(rateLimiter.OAuthCallback()).Get("/{provider}/callback",
				callback.New(log,
					oauthService,
					allowedRedirectHosts,
					cfg.OAuth.HandlersTimeout,
				),
			)

			// Authenticated — RequireAuth обязателен ДО rate limiter'ов,
			// использующих byUserID (им нужен claims в контексте).
			r.Group(func(r chi.Router) {
				r.Use(claimsParser.RequireAuth(appProvider))

				r.Get("/accounts",
					accounts.New(log, oauthService),
				)
				r.With(rateLimiter.OAuthLink()).Post("/{provider}/link",
					link.New(
						log,
						oauthService,
						allowedRedirectHosts,
						cfg.HTTPServer.HandlersTimeout,
					),
				)
				r.With(rateLimiter.OAuthUnlink()).Delete("/{provider}",
					unlink.New(log, oauthService, cfg.HTTPServer.HandlersTimeout),
				)
			})
		})
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
	default:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	}

	return log
}

func allowedRedirectHostSet(allowedHosts []string) map[string]bool {
	set := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		set[h] = true
	}
	return set
}
