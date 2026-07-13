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

// New godoc
// @Summary      Initiate OAuth login
// @Description  Starts the OAuth2 authorization flow for the given provider.
// @Description  Validates app_id and redirect_uri against the allowed hosts
// @Description  whitelist, then redirects the client to the provider's
// @Description  authorization URL (state is generated and tracked server-side).
// @Tags         oauth
// @Produce      json
// @Param        provider      path   string  true   "OAuth provider name (e.g. google, github)"
// @Param        app_id        query  integer true   "ID приложения-клиента" example(1)
// @Param        redirect_uri  query  string  true   "Callback URL after auth, must match allowed hosts" example("https://app.example.com/callback")
// @Success      302  "Redirect to provider's OAuth consent screen"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный app_id или redirect_uri не прошёл валидацию"  example({"status": "error", "error": "redirect_uri host not allowed"})
// @Failure      404  {object}  object{status=string,error=string}  "Неизвестный OAuth provider"  example({"status": "error", "error": "oauth provider not found"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка при формировании authorization URL"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/oauth/{provider}/login [get]
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
			log.Warn("redirect_uri rejected",
				slog.String("raw", r.URL.Query().Get("redirect_uri")),
				slog.Any("allowed_hosts", allowedHosts),
			)

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

			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
