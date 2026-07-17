package resendMagicLink

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
	SessionID string `json:"session_id" validate:"required"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Повторно отправить magic-link
// @Description  Инвалидирует предыдущую активную ссылку и высылает новую в
// @Description  рамках той же pending-сессии, начатой на /auth/login. Не
// @Description  подтверждает и не раскрывает факт доставки письма — ответ
// @Description  одинаковый независимо от того, дошло письмо или нет.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body  object{session_id=string}  true  "Идентификатор pending-сессии"  example({"session_id": "abcDEF123..."})
// @Success      200  {object}  object{status=string}  "Новая ссылка отправлена (либо попытка предпринята)"  example({"status": "ok"})
// @Failure      400  {object}  object{status=string,error=string}  "Невалидное тело запроса"  example({"status": "error", "error": "field SessionID is required"})
// @Failure      401  {object}  object{status=string,error=string}  "Pending-сессия не найдена или истекла — нужно начать логин заново"  example({"status": "error", "error": "session expired, please log in again"})
// @Failure      429  {object}  object{status=string,error=string}  "Слишком частые запросы на повторную отправку"  example({"status": "error", "error": "rate limit exceeded"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/2fa/magic-link/resend [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.resend.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request

		if err := render.DecodeJSON(r.Body, &req); err != nil {
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

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		if err := authMiddleware.TwoFA.Resend(ctx, req.SessionID); err != nil {
			if errors.Is(err, storage.ErrPendingSessionNotFound) {
				log.Warn("resend failed: pending session not found", sl.Err(err))
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("session expired, please log in again"))
				return
			}

			log.Error("failed to resend magic link", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))
			return
		}

		log.Info("magic link resent")

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
