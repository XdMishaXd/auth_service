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

// @Summary      Привязка OAuth-провайдера к существующему аккаунту
// @Description  Запускает OAuth2-процесс привязки стороннего OAuth-провайдера к аккаунту
// @Description  текущего аутентифицированного пользователя.
// @Description  Требует действительный access-токен. Идентификатор пользователя
// @Description  извлекается из его данных, а не из параметров запроса,
// @Description  поэтому привязка всегда выполняется для текущей сессии.
// @Tags         oauth
// @Security     BearerAuth
// @Produce      json
// @Param        provider      path   string  true  "Название OAuth-провайдера (например: google, github)"
// @Param        redirect_uri  query  string  true  "URL, на который будет выполнено перенаправление после завершения авторизации. Должен входить в список разрешённых адресов."
// @Success      200  {object}  Response  "Ссылка для перехода к OAuth-провайдеру"
// @Failure      400  {object}  object{status=string,error=string}  "Некорректный redirect_uri или app_id"
// @Failure      401  {object}  object{status=string,error=string}  "Access-токен отсутствует, недействителен или истёк"
// @Failure      404  {object}  object{status=string,error=string}  "OAuth-провайдер не поддерживается"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
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
