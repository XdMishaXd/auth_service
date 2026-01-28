package register

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
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username" validate:"required"`
	Pass     string `json:"password" validate:"required"`
}

type Response struct {
	resp.Response
	UserID int64 `json:"user_id"`
}

// New godoc
// @Summary      Регистрация нового пользователя
// @Description  ## Описание
// @Description  Создает новую учетную запись пользователя в системе и отправляет письмо с подтверждением email.
// @Description
// @Description  ### Процесс регистрации:
// @Description  1. Валидация входных данных (email формат, наличие username и пароля)
// @Description  2. Проверка уникальности email и username в базе данных
// @Description  3. Хеширование пароля с использованием bcrypt (cost factor 12)
// @Description  4. Создание записи пользователя в БД со статусом `email_verified = false`
// @Description  5. Генерация JWT токена верификации (валиден 24 часа)
// @Description  6. Отправка email с ссылкой подтверждения через RabbitMQ
// @Description
// @Description  ### Требования к данным:
// @Description  - **Email**: Валидный email формат (example@domain.com), должен быть уникальным
// @Description  - **Username**: Минимум 3 символа, только буквы, цифры и подчеркивание, должен быть уникальным
// @Description  - **Password**: Минимум 8 символов, рекомендуется использовать заглавные буквы, цифры и спецсимволы
// @Description
// @Description  ### Email верификация:
// @Description  - Письмо отправляется асинхронно через RabbitMQ (не блокирует ответ)
// @Description  - Токен верификации действует 24 часа
// @Description  - До подтверждения email пользователь не может войти в систему
// @Description  - Неподтвержденные аккаунты автоматически удаляются через 7 дней
// @Description
// @Description  ### Формат ссылки верификации:
// @Description  `http://domain.com/auth/verify?token=eyJhbGc...`
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user  body  object{email=string,username=string,password=string}  true  "Данные нового пользователя"  example({"email": "newuser@example.com", "username": "john_doe", "password": "SecurePass123!"})
// @Success      201  {object}  object{status=string,user_id=int}  "Пользователь успешно создан, письмо отправлено"  example({"status": "ok", "user_id": 42})
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации: некорректный email, слишком короткий пароль или отсутствуют обязательные поля"  example({"status": "error", "error": "Email must be a valid email address"})
// @Failure      409  {object}  object{status=string,error=string}  "Пользователь с таким email или username уже существует"  example({"status": "error", "error": "User with this email already exists"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка: проблемы с БД, RabbitMQ или email сервисом"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/register [post]
// @x-order      2
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
		const op = "handlers.register.New"

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

		userID, err := authMiddleware.RegisterNewUser(ctx, req.Email, req.Username, req.Pass)
		if err != nil {
			if errors.Is(err, storage.ErrUserAlreadyExists) {
				log.Error("Failed to register user: user already exists")

				render.Status(r, http.StatusConflict)
				render.JSON(w, r, resp.Error("User already exists"))

				return
			}

			log.Error("failed to register user", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("User registered", slog.Int64("id", userID))

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

		render.Status(r, http.StatusCreated)
		ResponseOK(w, r, userID)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, userID int64) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
		UserID:   userID,
	})
}
