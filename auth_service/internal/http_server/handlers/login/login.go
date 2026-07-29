package login

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
	Email string `json:"email" validate:"required,email" example:"example@domain.com"`
	Pass  string `json:"password" validate:"required" example:"SecurePass123!"`
	AppID int32  `json:"app_id" validate:"required,gt=0" example:"1"`
}

type response struct {
	resp.Response
	AccessToken      string `json:"access_token,omitempty" example:"abcDEF123..."`
	RefreshToken     string `json:"refresh_token,omitempty" example:"fkajeDJ1p3FJ..."`
	TwoFactorPending bool   `json:"two_factor_pending,omitempty" example:"true"`
	SessionID        string `json:"session_id,omitempty" example:"afsjeDJ1p3FJ..."`
}

// New godoc
// @Summary      Аутентификация пользователя
// @Description  ## Описание
// @Description  Выполняет аутентификацию пользователя по email и паролю. Если
// @Description  у пользователя включена magic-link 2FA, вместо токенов
// @Description  возвращается session_id для подтверждения через
// @Description  /auth/2fa/magic-link/verify; access/refresh в этом случае не выдаются.
// @Description
// @Description  ### Процесс аутентификации:
// @Description  1. Валидация входных данных (email формат, наличие пароля)
// @Description  2. Проверка существования пользователя в базе данных
// @Description  3. Верификация пароля (bcrypt hash comparison)
// @Description  4. Проверка статуса email (должен быть подтвержден)
// @Description  5. Валидация app_id (приложение должно существовать)
// @Description  6. Проверка статуса 2FA:
// @Description     - если выключена — генерация JWT токенов (access и refresh)
// @Description     - если включена — создание pending-сессии, отправка magic link на email, возврат session_id без токенов
// @Description
// @Description  ### Токены:
// @Description  - **Access Token**: JWT токен для доступа к защищенным ресурсам (TTL: 15 минут)
// @Description  - **Refresh Token**: JWT токен для обновления access токена (TTL: 30 дней)
// @Description  - **Session ID** (при включённой 2FA): используется для подтверждения через /auth/2fa/magic-link/verify, не является токеном доступа
// @Description
// @Description  ### Коды ошибок:
// @Description  - `400` - Некорректные данные (невалидный email, отсутствие полей, невалидный app_id)
// @Description  - `401` - Неверные credentials (пароль не совпадает; используется и для несуществующего email — не различается намеренно, во избежание user enumeration)
// @Description  - `403` - Email не подтвержден
// @Description  - `500` - Внутренняя ошибка сервера
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body  object{email=string,password=string,app_id=int}  true  "Данные для входа"
// @Success      200  {object}  object{status=string,access_token=string,refresh_token=string}  "Успешная аутентификация без 2FA"
// @Success      200  {object}  object{status=string,two_factor_pending=bool,session_id=string}  "Пароль верен, требуется подтверждение magic-link 2FA"
// @Failure      400  {object}  object{status=string,error=string}  "Ошибка валидации или невалидный app_id"
// @Failure      401  {object}  object{status=string,error=string}  "Неверные credentials"
// @Failure      403  {object}  object{status=string,error=string}  "Email не подтвержден"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка"
// @Router       /auth/login [post]
// @x-order      1
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.login.New"

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

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		loginResult, err := authMiddleware.Login(ctx, req.Email, req.Pass, req.AppID, pendingSessionTTL)
		if err != nil {
			status, msg := mapLoginError(reqLog, err)

			render.Status(r, status)
			render.JSON(w, r, resp.Error(msg))
			return
		}

		if loginResult.TwoFactorPending {
			reqLog.Info("password verified, 2fa challenge issued")
			responseTwoFAPending(w, r, loginResult.SessionID)
			return
		}

		reqLog.Info("User logged in successfully")
		responseOK(w, r, loginResult.AccessToken, loginResult.RefreshToken)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func responseTwoFAPending(w http.ResponseWriter, r *http.Request, sessionID string) {
	render.JSON(w, r, response{
		Response:         resp.OK(),
		TwoFactorPending: true,
		SessionID:        sessionID,
	})
}

// mapLoginError сопоставляет ошибку Login с HTTP-статусом и логирует
// её на подходящем уровне: Warn для ожидаемых бизнес-отказов,
// Error для непредвиденных сбоев.
func mapLoginError(reqLog *slog.Logger, err error) (statusCode int, errForReturn string) {
	switch {
	case errors.Is(err, storage.ErrUserNotFound), errors.Is(err, auth.ErrInvalidCredentials):
		reqLog.Warn("login rejected: invalid credentials")
		return http.StatusUnauthorized, "Invalid credentials"
	case errors.Is(err, auth.ErrInvalidAppID):
		reqLog.Warn("login rejected: invalid app id")
		return http.StatusBadRequest, "Invalid app id"
	case errors.Is(err, auth.ErrEmailNotVerified):
		reqLog.Warn("login rejected: email not verified")
		return http.StatusForbidden, "Email is not verified"
	case errors.Is(err, auth.ErrAccountDeleted):
		reqLog.Warn("login rejected: account deleted")
		return http.StatusGone, "Account deleted"
	default:
		reqLog.Error("failed to login user", sl.Err(err))
		return http.StatusInternalServerError, "Internal error"
	}
}
