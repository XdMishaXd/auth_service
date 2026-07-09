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
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type Request struct {
	Token   string `json:"token" validate:"required,reset_token_format"`
	NewPass string `json:"password" validate:"required,min=8"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Reset password
// @Description  Resets user password using a reset token received via email.
// @Description  The token must be provided in the request body in "selector.verifier" format,
// @Description  where selector is a UUID and verifier is a URL-safe base64 string.
// @Description  The token is single-use and is invalidated after a successful reset.
// @Description  The new password must be at least 8 characters and differ from the current password.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  object{token=string,password=string}  true  "Reset токен и новый пароль"  example({"token": "550e8400-e29b-41d4-a716-446655440000.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "password": "newSecurePass123"})
// @Success      200  {object}  object{status=string}  "Пароль успешно сброшен"  example({"status": "ok"})
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный формат токена, истёкший/использованный/неверный токен, некорректный пароль, либо пароль совпадает с текущим"  example({"status": "error", "error": "Invalid or expired token"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/password/reset [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.password.reset.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request

		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		log.Info("Request body decoded")

		var validateErr validator.ValidationErrors

		if errors.As(err, &validateErr) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.ValidationError(validateErr))
		} else {
			log.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))
		}

		parts := strings.SplitN(req.Token, ".", 2)

		if len(parts) != 2 {
			log.Warn("invalid reset token format")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid token"))
			return
		}

		if _, err := uuid.Parse(parts[0]); err != nil {
			log.Warn("invalid token id", sl.Err(err))

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
				log.Warn("reset password rejected", sl.Err(err))
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("Invalid or expired token"))
			case errors.Is(err, storage.ErrUserNotFound):
				// не должно светиться отдельным сообщением наружу — тот же генерик-ответ
				log.Error("reset token valid but user missing (data inconsistency)", sl.Err(err))
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("Invalid or expired token"))
			case errors.Is(err, auth.ErrSamePassword):
				log.Warn("new password same as current")
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("New password must differ from your current password"))
			default:
				log.Error("failed to reset password", sl.Err(err))
				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("internal error"))
			}

			return
		}

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
