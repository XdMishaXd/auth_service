package resendEmail

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/lib/verification"
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

// New godoc
// @Summary      Повторная отправка письма верификации
// @Description  ## Описание
// @Description  Повторно отправляет письмо с подтверждением email адреса пользователю.
// @Description
// @Description  ### Процесс отправки:
// @Description  1. Валидация email формата
// @Description  2. Проверка существования пользователя с указанным email
// @Description  3. Проверка статуса верификации email
// @Description  4. Если email не подтвержден - генерация нового токена верификации
// @Description  5. Отправка письма через RabbitMQ
// @Description  6. Возврат успешного ответа (независимо от статуса верификации)
// @Description
// @Description  ### Когда использовать:
// @Description  - Пользователь не получил первое письмо
// @Description  - Токен верификации истек (24 часа)
// @Description  - Письмо попало в спам
// @Description  - Пользователь случайно удалил письмо
// @Description
// @Description  ### Безопасность (важно!):
// @Description  - Endpoint всегда возвращает 200 OK, даже если email уже подтвержден
// @Description  - Это предотвращает enumeration атаки (определение существующих email)
// @Description  - Не раскрывает информацию о существовании пользователя
// @Description  - Rate limiting должен быть настроен (максимум 3 запроса в час на email)
// @Description
// @Description  ### Особенности:
// @Description  - Если email уже подтвержден - письмо не отправляется (но ответ 200 OK)
// @Description  - Новый токен инвалидирует предыдущий
// @Description  - Токен действителен 24 часа
// @Description  - Отправка асинхронная через RabbitMQ (не блокирует ответ)
// @Description
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email  body  object{email=string}  true  "Email пользователя"  example({"email": "user@example.com"})
// @Success      200  {object}  object{status=string}  "Письмо отправлено (или email уже подтвержден)"  example({"status": "ok"})
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации: некорректный email формат"  example({"status": "error", "error": "Email must be a valid email address"})
// @Failure      404  {object}  object{status=string,error=string}  "Пользователь не найден"  example({"status": "error", "error": "User not found"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/verify/resend [post]
// @x-order      6
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	msgSender verification.Publisher,
	verificationTokenTTL time.Duration,
	verificationTokenSecret string,
	address string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.resendVerificationEmail.New"

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

		if err := validate.Struct(req); err != nil {
			validateErr := err.(validator.ValidationErrors)

			log.Error("Invalid request", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.ValidationError(validateErr))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		userID, isVerified, err := authMiddleware.CheckUserVerification(ctx, req.Email)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Info("User not found")

				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, resp.Error("User not found"))

				return
			}

			log.Error("failed to check user verification", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		if !isVerified {
			err = verification.VerifyUserEmail(
				ctx,
				log,
				msgSender,
				verificationTokenTTL,
				verificationTokenSecret,
				userID,
				address,
				req.Email,
			)
			if err != nil {
				log.Error("Failed to send verification email", sl.Err(err))

				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("Internal error"))

				return
			}
		}

		log.Info("Email successfully resended", slog.Int64("uid", userID))

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
