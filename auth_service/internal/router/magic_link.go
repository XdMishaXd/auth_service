package router

import (
	"auth_service/internal/http_server/handlers/2fa/disable"
	"auth_service/internal/http_server/handlers/2fa/enable"
	requestAction "auth_service/internal/http_server/handlers/2fa/request_action_confirmation"
	resendMagicLink "auth_service/internal/http_server/handlers/2fa/resend_magic_link"
	verifyMagicLink "auth_service/internal/http_server/handlers/2fa/verify_magic_link"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"

	"github.com/go-chi/chi/v5"
)

func (rt *Router) registerMagicLink(r chi.Router) {
	d := rt.d
	t := d.Cfg.HTTPServer.HandlersTimeout

	r.Route("/2fa/magic-link", func(r chi.Router) {
		r.With(d.RateLimiter.MagicLinkVerify()).Post("/verify",
			verifyMagicLink.New(d.Log, d.Validate, d.Auth, t),
		)
		r.With(d.RateLimiter.MagicLinkResend()).Post("/resend",
			resendMagicLink.New(d.Log, d.Validate, d.Auth, t),
		)

		// Authenticated — требуют access-токен.
		r.Group(func(r chi.Router) {
			r.Use(claimsParser.RequireAuth(d.AppProvider))

			r.With(d.RateLimiter.MagicLinkEnable()).Post("/enable",
				enable.New(d.Log, d.Auth, t),
			)
			r.With(d.RateLimiter.MagicLinkDisable()).Post("/disable",
				disable.New(d.Log, d.Auth, t),
			)
			r.With(d.RateLimiter.Disable2FARequestConfirmation()).Post("/disable/request-confirmation",
				requestAction.NewDisable2FA(d.Log, d.Auth, t, d.Cfg.PendingSessionTTL),
			)
		})
	})
}
