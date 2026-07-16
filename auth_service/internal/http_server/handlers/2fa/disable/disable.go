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
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

type Request struct {
	Password  string `json:"password,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Token     string `json:"token,omitempty"`
}

// New godoc
// @Summary      Отключить magic-link 2FA
// @Description  Отключает magic-link 2FA. Подтверждение зависит от того, есть
// @Description  ли у пользователя пароль: если да — передаётся password; если
// @Description  нет (oauth-only аккаунт) — передаются session_id и token,
// @Description  полученные через /auth/2fa/magic-link/request-action-confirmation.
// @Tags         auth
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body  object{password=string,session_id=string,token=string}  false  "Подтверждение отключения (один из наборов полей)"  example({"password": "SecurePass123!"})
// @Success      200  {object}  object{status=string}  "2FA отключена"  example({"status": "ok"})
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк, либо неверное подтверждение (пароль/magic-link код)"  example({"status": "error", "error": "invalid confirmation"})
// @Failure      409  {object}  object{status=string,error=string}  "2FA не включена"  example({"status": "error", "error": "2fa is not enabled"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/2fa/magic-link/disable [post]
// @Router       /auth/2fa/magic-link/disable [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.disable.New"

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

		var req Request

		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err := authMiddleware.Disable2FA(
			ctx,
			claims.UserID,
			req.Password,
			req.SessionID,
			req.Token,
		)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrTwoFANotEnabled):
				render.Status(r, http.StatusConflict)
				render.JSON(w, r, resp.Error("2fa is not enabled"))
				return
			case errors.Is(err, auth.ErrDisableConfirmation):
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("invalid confirmation"))
				return
			}

			log.Error("failed to disable 2fa", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))
			return
		}

		log.Info("2fa disabled", slog.Int64("user_id", claims.UserID))

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
