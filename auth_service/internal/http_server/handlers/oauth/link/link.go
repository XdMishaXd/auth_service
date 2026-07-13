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

// New godoc
// @Summary      Link OAuth provider to existing account
// @Description  Starts OAuth2 flow to link a third-party provider to the
// @Description  currently authenticated user's account. Requires a valid
// @Description  access token; user_id is taken from claims, not request body,
// @Description  so the link is always bound to the authenticated session.
// @Tags         oauth
// @Security     BearerAuth
// @Produce      json
// @Param        provider      path   string  true   "OAuth provider name (e.g. google, github)"
// @Param        redirect_uri  query  string  true   "Callback URL after auth, must match allowed hosts" example("https://app.example.com/callback")
// @Success      200  {object}  Response  "Ссылка для перехода к провайдеру"  example({"status": "ok", "redirect_url": "https://accounts.google.com/o/oauth2/..."})
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный redirect_uri или app_id"  example({"status": "error", "error": "invalid app id"})
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"  example({"status": "error", "error": "invalid or expired access token"})
// @Failure      404  {object}  object{status=string,error=string}  "Неизвестный OAuth provider"  example({"status": "error", "error": "unknown oauth provider"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "internal server error"})
// @Router       /auth/oauth/{provider}/link [get]
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
