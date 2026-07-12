package link

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/lib/validation/oauthutil"

	"auth_service/internal/auth/oauth"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
	RedirectURL string `json:"redirect_url"`
}

func New(
	log *slog.Logger,
	authService *oauth.OAuthService,
	allowedHosts map[string]bool,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.link.New"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		claims, ok := claimsParser.ClaimsFromContext(r.Context())
		if !ok {
			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired access token"))

			return
		}

		providerName := chi.URLParam(r, "provider")

		redirectURI, err := oauthutil.ValidateRedirectURI(r.URL.Query().Get("redirect_uri"), allowedHosts)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error(err.Error()))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		authURL, err := authService.StartLogin(ctx, providerName, claims.AppID, redirectURI, claims.UserID)
		if err != nil {
			status, msg := mapStartLoginError(err)
			if status == http.StatusInternalServerError {
				log.Error("failed to start oauth link flow", sl.Err(err))
			}

			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))

			return
		}

		ResponseOK(w, r, authURL)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, redirectURL string) {
	render.JSON(w, r, Response{
		Response:    resp.OK(),
		RedirectURL: redirectURL,
	})
}

func mapStartLoginError(err error) (int, string) {
	switch {
	case errors.Is(err, oauth.ErrOAuthProviderNotFound):
		return http.StatusNotFound, "unknown oauth provider"
	case errors.Is(err, auth.ErrInvalidAppID):
		return http.StatusBadRequest, "invalid app id"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
