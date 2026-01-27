package verify

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/lib/verification"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Подтверждение email адреса
// @Description  ## Описание
// @Description  Подтверждает email адрес пользователя по токену из письма, активируя учетную запись.
// @Description
// @Description  ### Процесс верификации:
// @Description  1. Извлечение токена из query параметра `token`
// @Description  2. Валидация JWT токена (подпись, срок действия)
// @Description  3. Извлечение user_id из payload токена
// @Description  4. Проверка что пользователь существует и email еще не подтвержден
// @Description  5. Обновление статуса `email_verified = true` в базе данных
// @Description  6. Инвалидация токена (предотвращение повторного использования)
// @Description
// @Description  ### Особенности токена:
// @Description  - **Срок действия**: 24 часа с момента регистрации
// @Description  - **Формат**: JWT (JSON Web Token) подписанный HMAC-SHA256
// @Description  - **Одноразовый**: После успешной верификации токен инвалидируется
// @Description  - **Payload**: Содержит `user_id` и `exp` (время истечения)
// @Description
// @Description  ### После подтверждения:
// @Description  - Пользователь может войти в систему через `/auth/login`
// @Description  - Email помечен как подтвержденный навсегда
// @Description  - Опционально: отправка welcome email
// @Description
// @Description  ### Ошибки:
// @Description  - `400`: Токен отсутствует в URL
// @Description  - `401`: Токен невалидный, истек или уже использован
// @Description  - `500`: Ошибка базы данных
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        token  query  string  true  "JWT токен верификации из email"  example(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo0MiwiZXhwIjoxNzA2MTIzNDU2fQ.signature)
// @Success      200  {object}  object{status=string}  "Email успешно подтвержден, можно входить в систему"  example({"status": "ok"})
// @Failure      400  {object}  object{status=string,error=string}  "Токен отсутствует в URL"  example({"status": "error", "error": "missing token"})
// @Failure      401  {object}  object{status=string,error=string}  "Токен невалидный, истек или уже использован"  example({"status": "error", "error": "invalid or expired token"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "internal error"})
// @Router       /auth/verify [get]
// @x-order      5
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	tokenSecret string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.verify.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Warn("missing verification token")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("missing token"))

			return
		}

		userID, err := verification.ParseVerificationToken(token, tokenSecret)
		if err != nil {
			log.Warn("invalid verification token", sl.Err(err))

			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired token"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := authMiddleware.VerifyUser(ctx, token, tokenSecret); err != nil {
			log.Error("failed to mark user as verified", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))

			return
		}

		log.Info("email verified successfully", slog.Int64("uid", userID))

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
