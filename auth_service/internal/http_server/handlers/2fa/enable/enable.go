package enable

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	"auth_service/internal/storage"

	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Включить magic-link 2FA
// @Description  Включает magic-link 2FA для текущего пользователя. Требует,
// @Description  чтобы у пользователя уже был рабочий фактор для будущего
// @Description  отключения (пароль или хотя бы один привязанный oauth-аккаунт) —
// @Description  иначе включение необратимо заблокирует доступ к аккаунту.
// @Tags         2fa
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  object{status=string}  "2FA включена"  example({"status": "ok"})
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"  example({"status": "error", "error": "invalid or expired access token"})
// @Failure      409  {object}  object{status=string,error=string}  "2FA уже включена, либо нет ни одного доступного фактора для будущего disable"  example({"status": "error", "error": "no password or linked oauth account to enable 2fa"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/2fa/magic-link/enable [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.login.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		claims, ok := claimsParser.ClaimsFromContext(r.Context())
		if !ok {
			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired access token"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err := authMiddleware.Enable2FA(ctx, claims.UserID)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrTwoFAAlreadyEnabled):
				render.Status(r, http.StatusConflict)
				render.JSON(w, r, resp.Error("2fa already enabled"))
				return
			case errors.Is(err, auth.ErrNoAuthFactorAvailable):
				render.Status(r, http.StatusConflict)
				render.JSON(w, r, resp.Error("no password or linked oauth account to enable 2fa"))
				return
			case errors.Is(err, storage.ErrUserNotFound):
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, resp.Error("user not found"))
				return
			}

			log.Error("failed to enable 2fa", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("2fa enabled", slog.Int64("user_id", claims.UserID))

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
