package router

import (
	requestAction "auth_service/internal/http_server/handlers/2fa/request_action_confirmation"
	deleteAccount "auth_service/internal/http_server/handlers/account/delete_account"
	requestRestoreConfirmation "auth_service/internal/http_server/handlers/account/request_restore_confirmation"
	"auth_service/internal/http_server/handlers/account/restore"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"

	"github.com/go-chi/chi/v5"
)

func (rt *Router) registerAccount(r chi.Router) {
	d := rt.d
	t := d.Cfg.HTTPServer.HandlersTimeout

	// Публичные эндпоинты — юзер soft-deleted, не может пройти
	// RequireAuth (Login блокирует его до восстановления).
	r.With(d.RateLimiter.AccountRestoreRequestConfirmation()).Post("/restore/request-confirmation",
		requestRestoreConfirmation.New(d.Log, d.Validate, d.Auth, t, d.Cfg.PendingSessionTTL),
	)
	r.With(d.RateLimiter.AccountRestore()).Post("/restore",
		restore.New(d.Log, d.Validate, d.Auth, t),
	)

	// Authenticated — требуют access-токен.
	r.Group(func(r chi.Router) {
		r.Use(claimsParser.RequireAuth(d.AppProvider))

		r.With(d.RateLimiter.AccountDeleteRequestConfirmation()).Post("/delete/request-confirmation",
			requestAction.NewDeleteAccount(d.Log, d.Auth, t, d.Cfg.PendingSessionTTL),
		)
		r.With(d.RateLimiter.AccountDelete()).Delete("/",
			deleteAccount.New(d.Log, d.Validate, d.Auth, t),
		)
	})
}
