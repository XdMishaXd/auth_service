package forgot

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/lib/mailer"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Email string `json:"email" validate:"required,email"`
}

type Response struct {
	resp.Response
}

// @Summary      Запрос на сброс пароля
// @Description  Запускает процесс сброса пароля для указанного адреса электронной почты.
// @Description  Независимо от того, существует ли аккаунт с указанным email,
// @Description  всегда возвращает ответ с кодом 200, чтобы исключить возможность
// @Description  определения существования аккаунтов.
// @Description  Если аккаунт существует, на указанный email будет отправлено
// @Description  письмо со ссылкой для сброса пароля. Ошибки отправки письма
// @Description  фиксируются на стороне сервера и не влияют на ответ API.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  object{email=string}  true  "Адрес электронной почты пользователя"
// @Success      200  {object}  object{status=string}  "Запрос успешно принят"
// @Failure      400  {object}  object{status=string,error=string}  "Некорректное тело запроса или ошибка валидации"
// @Failure      429  {object}  object{status=string,error=string}  "Превышен допустимый лимит запросов"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/password/forgot [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	msgSender mailer.Publisher,
	authMiddleware *auth.Auth,
	address string,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.password.forgot.New"

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

		if err = validate.Struct(req); err != nil {
			var validateErr validator.ValidationErrors

			if errors.As(err, &validateErr) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.ValidationError(validateErr))

				return
			}

			log.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		resetToken, err := authMiddleware.Forgot(ctx, req.Email)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Info("forgot password requested for non-existent email")
				ResponseOK(w, r)
				return
			}

			log.Error("failed to generate reset token", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		if err := mailer.SendResetPassEmail(ctx, msgSender, resetToken, address, req.Email); err != nil {
			log.Error("failed to send reset email, user will not receive it", sl.Err(err))
			ResponseOK(w, r)
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
