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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token" example:"fkajeDJ1p3FJ..."`
	RefreshToken string `json:"refresh_token" example:"abcDEF123..."`
}

// @Summary      Callback OAuth-провайдера
// @Description  Обрабатывает перенаправление от OAuth-провайдера после того, как пользователь предоставил или отклонил доступ.
// @Description  Проверяет параметр state на соответствие ранее сохранённому значению (авторизация или привязка аккаунта),
// @Description  обменивает код авторизации на токены провайдера и в зависимости от типа операции
// @Description  либо выдает новую пару access и refresh токенов,
// @Description  либо привязывает OAuth-провайдера к существующему аккаунту.
// @Tags         oauth
// @Produce      json
// @Param        provider  path   string  true  "Название OAuth-провайдера (например: google, github)"
// @Param        code      query  string  true  "Код авторизации, полученный от OAuth-провайдера"
// @Param        state     query  string  true  "Токен состояния (state), должен совпадать со значением, выданным при начале авторизации или привязки аккаунта"
// @Param        error     query  string  false "Код ошибки, возвращаемый OAuth-провайдером, если пользователь отказал в доступе"
// @Success      200  {object}  Response  "Успешная авторизация или привязка аккаунта"
// @Failure      400  {object}  object{status=string,error=string}  "Пользователь отказал в доступе, отсутствуют параметры code/state, указан некорректный app_id либо state недействителен или истёк"
// @Failure      403  {object}  object{status=string,error=string}  "Email, полученный от OAuth-провайдера, не подтверждён"
// @Failure      404  {object}  object{status=string,error=string}  "Указанный OAuth-провайдер не поддерживается"
// @Failure      409  {object}  object{status=string,error=string}  "Конфликт данных: аккаунт с таким email уже существует либо OAuth-провайдер уже привязан к другому аккаунту"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
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
	case errors.Is(err, oauth.ErrAccountPendingDeletion):
		return http.StatusGone, "Account deleted"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
