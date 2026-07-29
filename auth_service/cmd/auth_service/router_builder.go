package main

import (
	"log/slog"

	"auth_service/internal/auth"
	"auth_service/internal/auth/oauth"
	"auth_service/internal/auth/oauth/providers"
	"auth_service/internal/auth/twoFactorAuth"
	"auth_service/internal/config"
	httpRateLimit "auth_service/internal/http_server/middleware/rate_limiter"
	customValidator "auth_service/internal/lib/validation/custom_validator"
	metricsService "auth_service/internal/metrics"
	"auth_service/internal/rabbitmq"
	rateLimit "auth_service/internal/ratelimit"
	"auth_service/internal/router"

	"auth_service/internal/storage/postgres"
	redisClient "auth_service/internal/storage/redis"
)

func buildRouter(
	cfg *config.Config, log *slog.Logger,
	pg *postgres.Repo, rdb *redisClient.Repo,
	mq *rabbitmq.RabbitMQClient, limiter *rateLimit.Limiter,
) *router.Router {
	googleProvider := providers.NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleRedirectURL)
	githubProvider := providers.NewGitHubProvider(cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubRedirectURL)
	oauthProviders := map[string]oauth.Provider{"google": googleProvider, "github": githubProvider}

	twoFactorAuthService := twoFactorAuth.New(pg, rdb, mq, log, cfg)
	authService := auth.New(log, pg, pg, pg, twoFactorAuthService, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.ResetTokenTTL)
	oauthService := oauth.New(authService, log, pg, rdb, oauthProviders, cfg.StateTTL)

	return router.New(router.Deps{
		Log:                  log,
		Cfg:                  cfg,
		Validate:             customValidator.New(),
		Metrics:              metricsService.New(),
		RateLimiter:          httpRateLimit.New(limiter, log),
		Auth:                 authService,
		OAuth:                oauthService,
		AppProvider:          pg,
		MsgBroker:            mq,
		AllowedRedirectHosts: allowedRedirectHostSet(cfg.AllowedRedirectHosts),
	})
}

func allowedRedirectHostSet(allowedHosts []string) map[string]bool {
	set := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		set[h] = true
	}
	return set
}
