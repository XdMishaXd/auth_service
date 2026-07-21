package unlink

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth/oauth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

// @Summary      Отвязка OAuth-провайдера от аккаунта
// @Description  Удаляет связь между указанным OAuth-провайдером и аккаунтом
// @Description  текущего аутентифицированного пользователя.
// @Description  Если этот способ входа является последним доступным методом
// @Description  аутентификации, операция будет отклонена, чтобы предотвратить
// @Description  потерю доступа к аккаунту.
// @Tags         oauth
// @Security     BearerAuth
// @Param        provider  path  string  true  "Название OAuth-провайдера (например: google, github)"
// @Success      204  "OAuth-провайдер успешно отвязан"
// @Failure      401  {object}  object{status=string,error=string}  "Access-токен отсутствует, недействителен или истёк"
// @Failure      403  {object}  object{status=string,error=string}  "Нельзя отвязать последний доступный способ аутентификации"
// @Failure      404  {object}  object{status=string,error=string}  "У пользователя отсутствует привязка к указанному OAuth-провайдеру"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/oauth/{provider} [delete]
func New(
	log *slog.Logger,
	authService *oauth.OAuthService,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.unlink.New"

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

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err := authService.Unlink(ctx, claims.UserID, providerName)
		if err != nil {
			status, msg := mapUnlinkError(err)
			if status == http.StatusInternalServerError {
				log.Error("failed to unlink oauth account", sl.Err(err))
			}
			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))
			return
		}

		render.Status(r, http.StatusNoContent)
		ResponseOK(w, r)
	}
}

func mapUnlinkError(err error) (int, string) {
	switch {
	case errors.Is(err, oauth.ErrOAuthLastAuthMethod):
		return http.StatusForbidden, "cannot unlink last authentication method"
	case errors.Is(err, storage.ErrOAuthAccountNotFound):
		return http.StatusNotFound, "oauth account not found"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
