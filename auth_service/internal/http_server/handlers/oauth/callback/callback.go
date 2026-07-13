package callback

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	"auth_service/internal/auth/oauth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// New godoc
// @Summary      OAuth provider callback
// @Description  Handles the redirect from the OAuth provider after user consent.
// @Description  Validates state against the stored value (login or link flow),
// @Description  exchanges the authorization code for tokens, and either issues
// @Description  a new access/refresh token pair (login) or links the provider
// @Description  to the existing account (link), depending on how state was created.
// @Tags         oauth
// @Produce      json
// @Param        provider  path   string  true  "OAuth provider name (e.g. google, github)"
// @Param        code      query  string  true  "Authorization code issued by the provider"
// @Param        state     query  string  true  "Opaque state token, must match value issued in /login or /link"
// @Param        error     query  string  false "Error code returned by provider if user denied access"
// @Success      200  {object}  Response  "Пара access/refresh токенов"  example({"status": "ok", "access_token": "eyJ...", "refresh_token": "eyJ..."})
// @Failure      400  {object}  object{status=string,error=string}  "Пользователь отклонил доступ, отсутствуют code/state, невалидный app_id или state истёк/невалиден"  example({"status": "error", "error": "invalid or expired oauth state"})
// @Failure      403  {object}  object{status=string,error=string}  "Email не подтверждён провайдером"  example({"status": "error", "error": "email not verified by provider"})
// @Failure      404  {object}  object{status=string,error=string}  "Неизвестный OAuth provider"  example({"status": "error", "error": "unknown oauth provider"})
// @Failure      409  {object}  object{status=string,error=string}  "Конфликт: аккаунт с таким email уже существует, либо provider уже привязан"  example({"status": "error", "error": "account with this email already exists, log in and link instead"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "internal server error"})
// @Router       /auth/oauth/{provider}/callback [get]
func New(
	log *slog.Logger,
	authMiddleware *oauth.OAuthService,
	allowedHosts map[string]bool,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.callback.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		providerName := chi.URLParam(r, "provider")

		if errParam := r.URL.Query().Get("error"); errParam != "" {
			log.Warn("oauth provider returned error", slog.String("provider_error", errParam))
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("access denied by user"))
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("code and state are required"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		accessToken, refreshToken, err := authMiddleware.Callback(ctx, providerName, code, state)
		if err != nil {
			status, msg := mapOAuthCallbackError(err)
			if status == http.StatusInternalServerError {
				log.Error("oauth callback failed", sl.Err(err))
			}

			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))

			return
		}

		ResponseOK(w, r, accessToken, refreshToken)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func mapOAuthCallbackError(err error) (int, string) {
	switch {
	case errors.Is(err, oauth.ErrOAuthProviderNotFound):
		return http.StatusNotFound, "unknown oauth provider"
	case errors.Is(err, oauth.ErrOAuthStateInvalid):
		return http.StatusBadRequest, "invalid or expired oauth state"
	case errors.Is(err, oauth.ErrOAuthEmailNotVerified):
		return http.StatusForbidden, "email not verified by provider"
	case errors.Is(err, oauth.ErrOAuthAccountConflict):
		return http.StatusConflict, "account with this email already exists, log in and link instead"
	case errors.Is(err, storage.ErrOAuthAccountAlreadyLinked):
		return http.StatusConflict, "this oauth account is already linked to another user"
	case errors.Is(err, storage.ErrOAuthProviderAlreadyLinked):
		return http.StatusConflict, "you already have this provider linked"
	case errors.Is(err, auth.ErrInvalidAppID):
		return http.StatusBadRequest, "invalid app id"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
