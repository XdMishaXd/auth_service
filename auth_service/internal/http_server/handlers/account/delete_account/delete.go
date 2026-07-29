package deleteaccount

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
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type request struct {
	Password  string `json:"password,omitempty" example:"SecurePass123!"`
	SessionID string `json:"session_id,omitempty" example:"abcDEF123..."`
	Token     string `json:"token,omitempty" example:"fkajeDJ1p3FJ..."`
}

// New godoc
// @Summary      Удалить аккаунт
// @Description  Помечает аккаунт как удалённый (soft delete, grace period 7
// @Description  дней). Требует подтверждения: паролем (если он установлен)
// @Description  либо magic-link кодом, полученным через
// @Description  /account/delete/request-confirmation (для oauth-only
// @Description  пользователей без пароля). Все refresh-токены и активные
// @Description  сессии немедленно отзываются. Идемпотентно — повторный вызов
// @Description  на уже удалённый аккаунт не является ошибкой.
// @Tags         account
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body      Request  true  "Пароль ИЛИ session_id+code"
// @Success      204  "Аккаунт удалён"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный запрос"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует/невалиден, либо неверный пароль/код подтверждения"
// @Failure      429  {object}  object{status=string,error=string}  "Превышен лимит запросов"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /account [delete]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authService *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.account.delete.New"

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

		if err := validate.Struct(req); err != nil {
			var validateErr validator.ValidationErrors

			if errors.As(err, &validateErr) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.ValidationError(validateErr))

				return
			}

			reqLog.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))

			return
		}

		if !hasExactlyOneConfirmationMethod(req) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("provide either password or session_id+code, not both or neither"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		if err := authService.DeleteAccount(
			ctx,
			claims.UserID,
			req.Password,
			req.SessionID,
			req.Token,
		); err != nil {
			status, msg := mapDeleteAccountError(reqLog, err)
			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))
			return
		}

		reqLog.Info("account deleted")

		w.WriteHeader(http.StatusNoContent)
	}
}

// hasExactlyOneConfirmationMethod проверяет, что указан ровно один способ
// подтверждения — пароль ИЛИ session_id+token, не оба и не ни один.
func hasExactlyOneConfirmationMethod(req request) bool {
	hasPassword := req.Password != ""
	hasMagicLink := req.SessionID != "" && req.Token != ""
	return hasPassword != hasMagicLink
}

// mapDeleteAccountError сопоставляет ошибку DeleteAccount с HTTP-статусом
// и логирует её на подходящем уровне.
func mapDeleteAccountError(reqLog *slog.Logger, err error) (statusCode int, errForReturn string) {
	switch {
	case errors.Is(err, auth.ErrDeleteConfirmation):
		reqLog.Warn("delete account: confirmation failed")
		return http.StatusUnauthorized, "invalid confirmation"

	case errors.Is(err, storage.ErrUserNotFound):
		reqLog.Warn("user not found")
		return http.StatusNotFound, "user not found"

	default:
		reqLog.Error("failed to delete account")
		return http.StatusInternalServerError, "Internal error"
	}
}
