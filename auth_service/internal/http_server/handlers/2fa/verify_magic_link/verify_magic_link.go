package verifyMagicLink

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	twoFactorAuth "auth_service/internal/auth/2fa"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	SessionID string `json:"session_id" validate:"required" example:"abcDEF123..."`
	Token     string `json:"token" validate:"required" example:"fkajeDJ1p3FJ..."`
}

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token" example:"asffhr3FJ..."`
	RefreshToken string `json:"refresh_token" example:"dgsadfgDJ1p3FJ..."`
}

// New godoc
// @Summary      Подтверждение magic-link 2FA
// @Description  Завершает второй фактор аутентификации: проверяет токен из
// @Description  письма в связке с session_id, полученным на этапе /auth/login,
// @Description  и при успехе выдаёт access/refresh токены. Токен одноразовый —
// @Description  повторное использование того же токена или session_id отклоняется.
// @Tags         2fa
// @Accept       json
// @Produce      json
// @Param        request  body  object{session_id=string,token=string}  true  "Данные для подтверждения"
// @Success      200  {object}  object{status=string,access_token=string,refresh_token=string}  "2FA подтверждена, выданы токены"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидное тело запроса или ошибка валидации"
// @Failure      401  {object}  object{status=string,error=string}  "Токен невалиден, истёк, уже использован, либо сессия истекла"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/2fa/magic-link/verify [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.verifylink.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request

		if err := render.DecodeJSON(r.Body, &req); err != nil {
			log.Error("failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		if err := validate.Struct(req); err != nil {
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

		accessToken, refreshToken, err := authMiddleware.VerifyMagicLink(ctx, req.SessionID, req.Token)
		if err != nil {
			switch {
			case errors.Is(err, twoFactorAuth.ErrMagicLinkVerificationFailed),
				errors.Is(err, storage.ErrPendingSessionNotFound):
				log.Warn("magic link verification failed", sl.Err(err))

				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("invalid or expired confirmation"))

				return
			}

			log.Error("magic link verification: internal error", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("2fa verified, tokens issued")

		// ? redirect

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
