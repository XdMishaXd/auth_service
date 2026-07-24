package restore

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

// Request — ровно один из двух способов подтверждения: Password ИЛИ
// SessionID+Code. Email обязателен всегда — юзер не аутентифицирован,
// у него нет access-токена, чтобы определить его иначе.
type Request struct {
	Email     string `json:"email" validate:"required,email" example:"example@domain.com"`
	Password  string `json:"password,omitempty" example:"SecurePass123!"`
	SessionID string `json:"session_id,omitempty" example:"fkajeDJ1p3FJ..."`
	Token     string `json:"token,omitempty" example:"abcDEF123..."`
}

// New godoc
// @Summary      Восстановить удалённый аккаунт
// @Description  Отменяет soft-delete, если grace period (7 дней) ещё не
// @Description  истёк. Требует подтверждения: паролем (если он установлен)
// @Description  либо magic-link кодом, полученным через
// @Description  /account/restore/request-confirmation (для oauth-only
// @Description  пользователей без пароля). Неаутентифицированный эндпоинт.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        request  body  Request  true  "Email + (пароль ИЛИ session_id+code)"
// @Success      204  "Аккаунт восстановлен"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный запрос"
// @Failure      401  {object}  object{status=string,error=string}  "Неверный пароль или код подтверждения, аккаунт не найден, не был удалён или grace period истёк"
// @Failure      429  {object}  object{status=string,error=string}  "Превышен лимит запросов"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /account/restore [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authService *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.account.restore.New"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}
		if err := validate.Struct(req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}

		hasPassword := req.Password != ""
		hasMagicLink := req.SessionID != "" && req.Token != ""
		if hasPassword == hasMagicLink {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("provide either password or session_id+code, not both or neither"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err := authService.RestoreAccount(ctx, req.Email, req.Password, req.SessionID, req.Token)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrRestoreConfirmation),
				errors.Is(err, storage.ErrUserNotFound),
				errors.Is(err, storage.ErrNothingToRestore):
				log.Info("restore rejected", sl.Err(err), slog.String("email", req.Email))
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("invalid confirmation"))
				return
			default:
				log.Error("failed to restore account", sl.Err(err), slog.String("email", req.Email))
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("Internal error"))
				return
			}
		}

		log.Info("account restored", slog.String("email", req.Email))

		w.WriteHeader(http.StatusNoContent)
	}
}
