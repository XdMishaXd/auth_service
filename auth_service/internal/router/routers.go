package router

import (
	"log/slog"

	"auth_service/internal/auth"
	"auth_service/internal/auth/oauth"
	"auth_service/internal/config"
	"auth_service/internal/http_server/handlers/infrastructure/health"
	metricsHandler "auth_service/internal/http_server/handlers/infrastructure/metrics_handler"
	httpRateLimit "auth_service/internal/http_server/middleware/http_rate_limit"
	logformatter "auth_service/internal/http_server/middleware/log_formatter"
	metricsCollector "auth_service/internal/http_server/middleware/metrics_collector"
	jwtGen "auth_service/internal/lib/jwt_gen"
	metricsService "auth_service/internal/metrics"
	"auth_service/internal/rabbitmq"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
)

// Deps содержит все зависимости, необходимые для сборки HTTP-роутера:
// логгер, конфигурацию, сервисы аутентификации/OAuth, rate limiter,
// брокер сообщений и список разрешённых redirect-хостов для OAuth.
type Deps struct {
	Log                  *slog.Logger
	Cfg                  *config.Config
	Validate             *validator.Validate
	Metrics              *metricsService.Metrics
	RateLimiter          *httpRateLimit.RateLimit
	Auth                 *auth.Auth
	OAuth                *oauth.OAuthService
	AppProvider          jwtGen.AppSecretProvider
	MsgBroker            *rabbitmq.RabbitMQClient
	AllowedRedirectHosts map[string]bool
}

// Router собирает HTTP-роуты сервиса на основе переданных Deps.
type Router struct {
	d Deps
}

// New создаёт Router с переданными зависимостями d.
func New(d Deps) *Router {
	return &Router{d: d}
}

// Setup строит и возвращает *chi.Mux со всеми зарегистрированными
// маршрутами: health/metrics без middleware, остальные — под общим
// стеком middleware (request ID, real IP, логирование, recover).
func (rt *Router) Setup() *chi.Mux {
	r := chi.NewRouter()

	r.Get("/health", health.New())
	r.Get("/metrics", metricsHandler.New(rt.d.Metrics))

	r.Group(func(r chi.Router) {
		r.Use(metricsCollector.New(rt.d.Metrics))
		r.Use(middleware.RequestID)
		r.Use(middleware.ClientIPFromHeader("X-Real-IP"))
		r.Use(logformatter.NewRedactingLogger())
		r.Use(middleware.Recoverer)

		rt.registerSwagger(r)

		r.Route("/auth", func(r chi.Router) {
			rt.registerCoreAuth(r)
			rt.registerOAuth(r)
			rt.registerMagicLink(r)
		})

		r.Route("/account", func(r chi.Router) {
			rt.registerAccount(r)
		})
	})

	return r
}
