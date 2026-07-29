package disable

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type response struct {
	resp.Response
}

type request struct {
	Password  string `json:"password,omitempty" example:"SecurePass123!"`
	SessionID string `json:"session_id,omitempty" example:"abcDEF123..."`
	Token     string `json:"token,omitempty" example:"fkajeDJ1p3FJ..."`
}

// New godoc
// @Summary      Отключить magic-link 2FA
// @Description  Отключает magic-link 2FA. Подтверждение зависит от того, есть
// @Description  ли у пользователя пароль: если да — передаётся password; если
// @Description  нет (oauth-only аккаунт) — передаются session_id и token,
// @Description  полученные через /auth/2fa/magic-link/request-action-confirmation.
// @Tags         2fa
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body  object{password=string,session_id=string,token=string}  false  "Подтверждение отключения (один из наборов полей)"
// @Success      200  {object}  object{status=string}  "2FA отключена"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк, либо неверное подтверждение (пароль/magic-link код)"
// @Failure      409  {object}  object{status=string,error=string}  "2FA не включена"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/2fa/magic-link/disable [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.disable.New"

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

		var req request

		if err := render.DecodeJSON(r.Body, &req); err != nil {
			reqLog.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		if err := authMiddleware.Disable2FA(
			ctx,
			claims.UserID,
			req.Password,
			req.SessionID,
			req.Token,
		); err != nil {
			status, msg := mapDisable2FAError(reqLog, err)
			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))
			return
		}

		reqLog.Info("2fa disabled")

		responseOK(w, r)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, response{
		Response: resp.OK(),
	})
}

// mapDisable2FAError сопоставляет ошибку Disable2FA с HTTP-статусом
// и логирует её на подходящем уровне.
func mapDisable2FAError(reqLog *slog.Logger, err error) (statusCode int, errForReturn string) {
	switch {
	case errors.Is(err, auth.ErrTwoFANotEnabled):
		reqLog.Warn("disable 2fa rejected: not enabled")
		return http.StatusConflict, "2fa is not enabled"

	case errors.Is(err, auth.ErrDisableConfirmation):
		reqLog.Warn("disable 2fa rejected: invalid confirmation")
		return http.StatusUnauthorized, "invalid confirmation"

	default:
		reqLog.Error("failed to disable 2fa", sl.Err(err))
		return http.StatusInternalServerError, "Internal error"
	}
}
