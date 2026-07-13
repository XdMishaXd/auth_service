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

// New godoc
// @Summary      Unlink OAuth provider from account
// @Description  Removes the link between the given OAuth provider and the
// @Description  currently authenticated user. Fails if this is the user's
// @Description  last remaining authentication method, to prevent account lockout.
// @Tags         oauth
// @Security     BearerAuth
// @Param        provider  path  string  true  "OAuth provider name (e.g. google, github)"
// @Success      204  "Провайдер успешно отвязан"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"  example({"status": "error", "error": "invalid or expired access token"})
// @Failure      403  {object}  object{status=string,error=string}  "Нельзя отвязать последний метод аутентификации"  example({"status": "error", "error": "cannot unlink last authentication method"})
// @Failure      404  {object}  object{status=string,error=string}  "OAuth-аккаунт с таким provider не найден у пользователя"  example({"status": "error", "error": "oauth account not found"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "internal server error"})
// @Router       /auth/oauth/{provider}/unlink [delete]
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

		w.WriteHeader(http.StatusNoContent)
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
