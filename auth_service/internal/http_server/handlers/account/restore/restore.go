package restore

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type request struct {
	Email     string `json:"email" validate:"required,email" example:"example@domain.com"`
	Password  string `json:"password,omitempty" example:"SecurePass123!"`
	SessionID string `json:"session_id,omitempty" example:"fkajeDJ1p3FJ..."`
	Token     string `json:"token,omitempty" example:"abcDEF123..."`
	AppID     int32  `json:"app_id" validate:"required,gt=0" example:"1"`
}

type response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// New godoc
// @Summary      Восстановить удалённый аккаунт
// @Description  Отменяет soft-delete, если grace period (7 дней) ещё не
// @Description  истёк, и сразу выдаёт access/refresh токены. Требует
// @Description  подтверждения: паролем (если он установлен) либо
// @Description  magic-link токеном, полученным через
// @Description  /account/restore/request-confirmation (для oauth-only
// @Description  пользователей без пароля). Неаутентифицированный эндпоинт.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        request  body      Request  true  "Email + (пароль ИЛИ session_id+token) + app_id"
// @Success      200  {object}  Response       "Аккаунт восстановлен, выданы токены"
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

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			reqLog.Error("failed to decode request body", sl.Err(err))
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
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

		hasPassword := req.Password != ""
		hasMagicLink := req.SessionID != "" && req.Token != ""
		if hasPassword == hasMagicLink {
			reqLog.Warn("restore rejected: ambiguous confirmation method")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("provide either password or session_id+code, not both or neither"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		accessToken, refreshToken, err := authService.RestoreAccount(
			ctx,
			req.Email,
			req.Password,
			req.SessionID,
			req.Token,
			req.AppID,
		)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrRestoreConfirmation),
				errors.Is(err, storage.ErrUserNotFound),
				errors.Is(err, storage.ErrNothingToRestore):
				reqLog.Warn("restore rejected", sl.Err(err))
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("invalid confirmation"))
				return
			default:
				reqLog.Error("failed to restore account", sl.Err(err))
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("Internal error"))
				return
			}
		}

		reqLog.Info("account restored")

		responseOK(w, r, accessToken, refreshToken)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
