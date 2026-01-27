package refresh

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
	RefreshToken string `json:"refresh_token"`
}

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// New godoc
// @Summary      Обновление access токена
// @Description  ## Описание
// @Description  Обменивает действующий refresh токен на новую пару токенов (access и refresh).
// @Description
// @Description  ### Процесс обновления:
// @Description  1. Валидация refresh токена (подпись JWT, срок действия)
// @Description  2. Извлечение user_id и app_id из payload токена
// @Description  3. Проверка что токен не находится в blacklist (Redis)
// @Description  4. Проверка статуса пользователя (не заблокирован, email подтвержден)
// @Description  5. Генерация новой пары токенов:
// @Description     - Новый access токен (TTL: 15 минут)
// @Description     - Новый refresh токен (TTL: 30 дней)
// @Description  6. Инвалидация старого refresh токена (token rotation)
// @Description  7. Сохранение нового refresh токена в БД
// @Description
// @Description  ### Token Rotation (безопасность):
// @Description  - **Каждый refresh токен одноразовый** — после использования старый токен инвалидируется
// @Description  - Это защищает от атак с украденными токенами
// @Description  - При попытке использовать старый токен — все сессии пользователя инвалидируются
// @Description
// @Description  ### Время жизни токенов:
// @Description  - **Access Token**: 15 минут (короткий для безопасности)
// @Description  - **Refresh Token**: 30 дней (удобство для пользователя)
// @Description  - Если пользователь неактивен 30 дней — требуется повторный login
// @Description
// @Description  ### Когда использовать:
// @Description  - Access токен истек (получили 401 на защищенном endpoint)
// @Description  - Превентивное обновление перед истечением access токена
// @Description  - После длительного простоя приложения
// @Description
// @Description  ### Ошибки:
// @Description  - `400`: Невалидный JSON или отсутствует refresh_token
// @Description  - `401`: Токен истек, невалиден или уже использован
// @Description  - `403`: Пользователь заблокирован
// @Description  - `500`: Ошибка БД или генерации токенов
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        token  body  object{refresh_token=string}  true  "Текущий refresh токен"  example({"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."})
// @Success      200  {object}  object{status=string,access_token=string,refresh_token=string}  "Новая пара токенов"  example({"status": "ok", "access_token": "eyJhbGc...", "refresh_token": "eyJhbGc..."})
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации"  example({"status": "error", "error": "refresh_token is required"})
// @Failure      401  {object}  object{status=string,error=string}  "Невалидный или истекший токен"  example({"status": "error", "error": "Invalid credentials"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/refresh [post]
// @x-order      3
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.refresh.New"

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

		accessToken, newRefreshToken, err := authMiddleware.Refresh(ctx, req.RefreshToken)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("Invalid credentials"))

				return
			}

			log.Error("failed to refresh tokens", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("Tokens refreshed successfully")

		ResponseOK(w, r, accessToken, newRefreshToken)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
