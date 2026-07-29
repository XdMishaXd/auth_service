package reset

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type request struct {
	Token   string `json:"token" validate:"required,reset_token_format" example:"abcDEF123..."` //nolint:revive // custom validator
	NewPass string `json:"password" validate:"required,min=8" example:"SecurePass123!"`
}

type response struct {
	resp.Response
}

// New godoc
// @Summary      Сброс пароля
// @Description  Сбрасывает пароль пользователя с использованием токена,
// @Description  полученного по электронной почте.
// @Description  Токен должен быть передан в теле запроса в формате
// @Description  "selector.verifier", где selector — UUID, а verifier —
// @Description  строка в формате URL-safe Base64.
// @Description  Токен можно использовать только один раз. После успешного
// @Description  сброса пароля он становится недействительным.
// @Description  Новый пароль должен содержать не менее 8 символов и
// @Description  отличаться от текущего пароля.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  object{token=string,password=string}  true  "Токен для сброса пароля и новый пароль"
// @Success      200  {object}  object{status=string}  "Пароль успешно сброшен"
// @Failure      400  {object}  object{status=string,error=string}  "Некорректный формат токена, токен недействителен, истёк или уже был использован, пароль не соответствует требованиям либо совпадает с текущим"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/password/reset [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.password.reset.New"

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req request

		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			reqLog.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		if err = validate.Struct(req); err != nil {
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

		parts := strings.SplitN(req.Token, ".", 2)

		if len(parts) != 2 {
			reqLog.Warn("invalid reset token format")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid token"))
			return
		}

		if _, err := uuid.Parse(parts[0]); err != nil {
			reqLog.Warn("invalid token id", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid token"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err = authMiddleware.ResetPassword(ctx, parts[0], parts[1], req.NewPass)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrInvalidCredentials),
				errors.Is(err, storage.ErrResetTokenNotFound),
				errors.Is(err, auth.ErrResetTokenExpired),
				errors.Is(err, auth.ErrResetTokenUsed):
				reqLog.Warn("reset password rejected", sl.Err(err))
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("Invalid or expired token"))
			case errors.Is(err, storage.ErrUserNotFound):
				// не должно светиться отдельным сообщением наружу — тот же генерик-ответ
				reqLog.Error("reset token valid but user missing (data inconsistency)", sl.Err(err))
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("Invalid or expired token"))
			case errors.Is(err, auth.ErrSamePassword):
				reqLog.Warn("new password same as current")
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("New password must differ from your current password"))
			default:
				reqLog.Error("failed to reset password", sl.Err(err))
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("internal error"))
			}

			return
		}

		log.Info("password has been successfully reset")

		responseOK(w, r)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, response{
		Response: resp.OK(),
	})
}
