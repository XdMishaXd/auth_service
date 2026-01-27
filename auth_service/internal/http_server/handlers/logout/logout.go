package logout

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Выход из системы
// @Description  ## Описание
// @Description  Завершает активную сессию пользователя, инвалидируя refresh токен.
// @Description
// @Description  ### Процесс выхода:
// @Description  1. Валидация refresh токена из тела запроса
// @Description  2. Проверка существования токена в базе данных
// @Description  3. Добавление токена в blacklist (Redis)
// @Description  4. Удаление токена из таблицы активных сессий
// @Description  5. Инвалидация связанного access токена
// @Description
// @Description  ### Особенности:
// @Description  - После logout refresh токен больше нельзя использовать для получения новых access токенов
// @Description  - Access токен технически остается валидным до истечения TTL (~15 минут)
// @Description  - Для немедленной инвалидации access токена используется blacklist в Redis
// @Description  - Поддержка "logout from all devices" (опционально)
// @Description
// @Description  ### Безопасность:
// @Description  - Токен в blacklist хранится только до истечения его TTL
// @Description  - При попытке использовать инвалидированный токен возвращается 401
// @Description  - Логирование всех операций logout для аудита
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        token  body  object{refresh_token=string}  true  "Refresh токен для инвалидации"  example({"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."})
// @Success      200  {object}  object{status=string}  "Успешный выход из системы"  example({"status": "ok"})
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации: токен не передан или некорректный JSON"  example({"status": "error", "error": "refresh_token is required"})
// @Failure      401  {object}  object{status=string,error=string}  "Невалидный или истекший refresh токен"  example({"status": "error", "error": "Invalid credentials"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/logout [post]
// @x-order      4
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.logout.New"

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

		if err := authMiddleware.Logout(ctx, req.RefreshToken); err != nil {
			log.Error("failed to logout user", sl.Err(err))

			if errors.Is(err, auth.ErrInvalidCredentials) {
				render.Status(r, http.StatusUnauthorized)

				render.JSON(w, r, resp.Error("invalid credentials"))

				return
			}

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("user logged out successfully")

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
