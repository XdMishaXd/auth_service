package login

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

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Email string `json:"email" validate:"required,email"`
	Pass  string `json:"password" validate:"required"`
	AppID int32  `json:"app_id" validate:"required"`
}

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// New godoc
// @Summary      Аутентификация пользователя
// @Description  ## Описание
// @Description  Выполняет аутентификацию пользователя по email и паролю, возвращает пару токенов (access и refresh).
// @Description
// @Description  ### Процесс аутентификации:
// @Description  1. Валидация входных данных (email формат, наличие пароля)
// @Description  2. Проверка существования пользователя в базе данных
// @Description  3. Верификация пароля (bcrypt hash comparison)
// @Description  4. Проверка статуса email (должен быть подтвержден)
// @Description  5. Валидация app_id (приложение должно существовать)
// @Description  6. Генерация JWT токенов (access и refresh)
// @Description
// @Description  ### Токены:
// @Description  - **Access Token**: JWT токен для доступа к защищенным ресурсам (TTL: 15 минут)
// @Description  - **Refresh Token**: JWT токен для обновления access токена (TTL: 30 дней)
// @Description
// @Description  ### Коды ошибок:
// @Description  - `400` - Некорректные данные (невалидный email, отсутствие полей)
// @Description  - `401` - Неверные credentials (пароль не совпадает)
// @Description  - `403` - Email не подтвержден
// @Description  - `404` - Пользователь или приложение не найдены
// @Description  - `500` - Внутренняя ошибка сервера
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body  object{email=string,password=string,app_id=int}  true  "Данные для входа"  example({"email": "user@example.com", "password": "SecurePass123!", "app_id": 1})
// @Success      200  {object}  object{status=string,access_token=string,refresh_token=string}  "Успешная аутентификация"  example({"status": "ok", "access_token": "eyJhbGc...", "refresh_token": "eyJhbGc..."})
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации"  example({"status": "error", "error": "Invalid email format"})
// @Failure      401  {object}  object{status=string,error=string}  "Неверные credentials"  example({"status": "error", "error": "Invalid credentials"})
// @Failure      403  {object}  object{status=string,error=string}  "Email не подтвержден"  example({"status": "error", "error": "Email is not verified"})
// @Failure      404  {object}  object{status=string,error=string}  "Пользователь не найден"  example({"status": "error", "error": "User not found"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/login [post]
// @x-order      1
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.login.New"

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

		accessToken, refreshToken, err := authMiddleware.Login(ctx, req.Email, req.Pass, req.AppID)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrUserNotFound):
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, resp.Error("User not found"))
				return
			case errors.Is(err, auth.ErrInvalidCredentials):
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("Invalid credentials"))
				return
			case errors.Is(err, auth.ErrInvalidAppID):
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.Error("Invalid app id"))
				return
			case errors.Is(err, auth.ErrEmailNotVerified):
				render.Status(r, http.StatusForbidden)
				render.JSON(w, r, resp.Error("email is not verified"))
				return
			}

			log.Error("failed to login user", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("User logged in successfully")

		ResponseOK(w, r, accessToken, refreshToken)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
