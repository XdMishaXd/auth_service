package ologin

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"auth_service/internal/auth/oauth"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/validation/oauthutil"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

func New(
	log *slog.Logger,
	authMiddleware *oauth.OAuthService,
	allowedHosts map[string]bool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.login.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		providerName := chi.URLParam(r, "provider")

		appIDStr := r.URL.Query().Get("app_id")
		appID64, err := strconv.ParseInt(appIDStr, 10, 32)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid app_id"))
			return
		}

		redirectURI, err := oauthutil.ValidateRedirectURI(r.URL.Query().Get("redirect_uri"), allowedHosts)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error(err.Error()))
			return
		}

		authURL, err := authMiddleware.StartLogin(r.Context(), providerName, int32(appID64), redirectURI, 0)
		if err != nil {
			switch {
			case errors.Is(err, oauth.ErrOAuthProviderNotFound):
				render.Status(r, http.StatusNotFound)
			default:
				render.Status(r, http.StatusInternalServerError)
			}

			render.JSON(w, r, resp.Error(err.Error()))

			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
