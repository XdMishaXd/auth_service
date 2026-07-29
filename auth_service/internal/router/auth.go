package router

import (
	"auth_service/internal/http_server/handlers/login"
	"auth_service/internal/http_server/handlers/logout"
	"auth_service/internal/http_server/handlers/password/forgot"
	"auth_service/internal/http_server/handlers/password/reset"
	"auth_service/internal/http_server/handlers/refresh"
	"auth_service/internal/http_server/handlers/register"
	resendVerification "auth_service/internal/http_server/handlers/resend_verification_email"
	"auth_service/internal/http_server/handlers/verify"

	"github.com/go-chi/chi/v5"
)

func (rt *Router) registerCoreAuth(r chi.Router) {
	d := rt.d
	t := d.Cfg.HTTPServer.HandlersTimeout

	r.With(d.RateLimiter.Register()).Post("/register",
		register.New(
			d.Log,
			d.Validate,
			d.Auth,
			d.MsgBroker,
			d.Cfg.VerificationTokenTTL,
			d.Cfg.VerificationTokenSecret,
			"",
			t,
		),
	)
	r.With(d.RateLimiter.Login()).Post("/login",
		login.New(d.Log, d.Validate, d.Auth, t, d.Cfg.PendingSessionTTL),
	)
	r.With(d.RateLimiter.Refresh()).Post("/refresh",
		refresh.New(d.Log, d.Validate, d.Auth, t),
	)
	r.With(d.RateLimiter.Logout()).Post("/logout",
		logout.New(d.Log, d.Validate, d.Auth, t),
	)
	r.With(d.RateLimiter.Verify()).Get("/verify",
		verify.New(d.Log, d.Auth, d.Cfg.VerificationTokenSecret, t),
	)
	r.With(d.RateLimiter.ResendVerificationEmail()).Post("/verify/resend",
		resendVerification.New(
			d.Log,
			d.Validate,
			d.Auth,
			d.MsgBroker,
			d.Cfg.VerificationTokenTTL,
			d.Cfg.VerificationTokenSecret,
			"",
			t,
		),
	)
	r.With(d.RateLimiter.ForgotPassword()).Post("/password/forgot",
		forgot.New(
			d.Log,
			d.Validate,
			d.MsgBroker,
			d.Auth,
			d.Cfg.HTTPServer.Address, //nolint:staticcheck // QF1008: селектор через встроенное поле оставлен явно для читаемости
			t,
		),
	)
	r.With(d.RateLimiter.ResetPassword()).Post("/password/reset",
		reset.New(d.Log, d.Validate, d.Auth, t),
	)
}
