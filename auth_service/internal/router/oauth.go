package router

import (
	"auth_service/internal/http_server/handlers/oauth/accounts"
	"auth_service/internal/http_server/handlers/oauth/callback"
	"auth_service/internal/http_server/handlers/oauth/link"
	ologin "auth_service/internal/http_server/handlers/oauth/login"
	"auth_service/internal/http_server/handlers/oauth/unlink"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"

	"github.com/go-chi/chi/v5"
)

func (rt *Router) registerOAuth(r chi.Router) {
	d := rt.d
	t := d.Cfg.OAuth.HandlersTimeout

	r.Route("/oauth", func(r chi.Router) {
		// Публичные эндпоинты — юзер ещё не аутентифицирован.
		r.With(d.RateLimiter.OAuthLogin()).Get("/{provider}/login",
			ologin.New(d.Log, d.OAuth, d.AllowedRedirectHosts),
		)
		r.With(d.RateLimiter.OAuthCallback()).Get("/{provider}/callback",
			callback.New(d.Log, d.OAuth, t),
		)

		// Authenticated — RequireAuth обязателен ДО rate limiter'ов,
		// использующих byUserID (им нужен claims в контексте).
		r.Group(func(r chi.Router) {
			r.Use(claimsParser.RequireAuth(d.AppProvider))

			r.Get("/accounts",
				accounts.New(d.Log, d.OAuth, t),
			)
			r.With(d.RateLimiter.OAuthLink()).Post("/{provider}/link",
				link.New(d.Log, d.OAuth, d.AllowedRedirectHosts, d.Cfg.HTTPServer.HandlersTimeout),
			)
			r.With(d.RateLimiter.OAuthUnlink()).Delete("/{provider}",
				unlink.New(d.Log, d.OAuth, d.Cfg.HTTPServer.HandlersTimeout),
			)
		})
	})
}
