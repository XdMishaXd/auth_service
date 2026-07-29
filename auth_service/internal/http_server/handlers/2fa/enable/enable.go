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

type response struct {
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
// @Success      200  {object}  object{status=string}  "2FA включена"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"
// @Failure      409  {object}  object{status=string,error=string}  "2FA уже включена, либо нет ни одного доступного фактора для будущего disable"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/2fa/magic-link/enable [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.enable.New"

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		claims, ok := claimsParser.ClaimsFromContext(r.Context())
		if !ok {
			reqLog.Error("claims missing from context after RequireAuth")

			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired access token"))
			return
		}

		reqLog = reqLog.With(slog.Int64("user_id", claims.UserID))

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err := authMiddleware.Enable2FA(ctx, claims.UserID)
		if err != nil {
			status, msg := mapEnable2FAError(reqLog, err)

			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))
			return
		}

		reqLog.Info("2fa enabled", slog.Int64("user_id", claims.UserID))

		responseOK(w, r)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, response{
		Response: resp.OK(),
	})
}

// mapEnable2FAError сопоставляет ошибку Enable2FA с HTTP-статусом
// и логирует её на подходящем уровне.
func mapEnable2FAError(reqLog *slog.Logger, err error) (statusCode int, errForReturn string) {
	switch {
	case errors.Is(err, auth.ErrTwoFAAlreadyEnabled):
		reqLog.Warn("enable 2fa rejected: already enabled")
		return http.StatusConflict, "2fa already enabled"

	case errors.Is(err, auth.ErrNoAuthFactorAvailable):
		reqLog.Warn("enable 2fa rejected: no auth factor available")
		return http.StatusConflict, "no password or linked oauth account to enable 2fa"

	case errors.Is(err, storage.ErrUserNotFound):
		reqLog.Warn("enable 2fa rejected: user not found")
		return http.StatusNotFound, "user not found"

	default:
		reqLog.Error("failed to enable 2fa", sl.Err(err))
		return http.StatusInternalServerError, "Internal error"
	}
}
